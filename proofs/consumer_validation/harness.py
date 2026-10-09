"""Transparent observations of the Phase 1 consumer path."""
import base64
import copy
import hashlib
import json
from datetime import datetime, timezone
from unittest.mock import patch

import bson.json_util
import saga.config
import saga.common.crypto as sc
import saga.common.contact_policy as policy
from saga.agent import Agent
from proofs.decision_bridge.bridge import evaluate, fingerprint, policy_hash
from proofs.consumer_validation.fixtures import INITIATOR, RECEIVER, b64, raw_public, pem


def digest(value):
    return hashlib.sha256(value).hexdigest()


class Recorder:
    def __init__(self, case_id):
        self.case_id = case_id
        self.events = []

    def add(self, stage, **data):
        self.events.append({"seq": len(self.events) + 1, "case_id": self.case_id,
                            "attempt_id": "1", "stage": stage, **copy.deepcopy(data)})

    def matcher(self, consumer, original):
        def observed(rules, aid):
            snapshot = copy.deepcopy(rules)
            try:
                result = original(rules, aid)
            except Exception as exc:
                self.add("matcher", consumer=consumer, rules=snapshot, target=aid,
                         status="error", exception=type(exc).__name__)
                raise
            self.add("matcher", consumer=consumer, rules=snapshot, target=aid,
                     rules_sha256=fingerprint(snapshot), status="returned", budget=result)
            return result
        return observed


class MemoryConnection:
    """Byte transport only. There are no conversation frames to receive."""
    def __init__(self, handshake, peer_cert, recorder):
        payload = json.dumps(handshake).encode()
        self.incoming = len(payload).to_bytes(4, "big") + payload
        self.peer_cert = peer_cert
        self.recorder = recorder
        self.sent = []
        self.closed = False
        self.extra_reads = 0

    def recv(self, size):
        if not self.incoming:
            self.extra_reads += 1
            raise AssertionError("Read beyond the handshake: conversation is forbidden")
        chunk, self.incoming = self.incoming[:size], self.incoming[size:]
        return chunk

    def sendall(self, data):
        if int.from_bytes(data[:4], "big") != len(data) - 4:
            raise AssertionError("Invalid production framing")
        message = json.loads(data[4:])
        self.sent.append(message)
        self.recorder.add("receiver_send", keys=sorted(message),
                          token_sha256=digest(message["token"].encode()) if "token" in message else None)

    def getpeercert(self, binary_form=False):
        if not binary_form:
            raise AssertionError("Only production DER certificate access is supported")
        return self.peer_cert

    def shutdown(self, how):
        pass

    def close(self):
        self.closed = True


def snapshot(provider, receiver):
    document = provider.agents_collection.find_one({"aid": RECEIVER})
    return {"provider_otks": [digest(bytes(k)) for k in document["one_time_keys"]],
            "provider_otk_sigs": [digest(bytes(k)) for k in document["one_time_key_sigs"]],
            "counter": document["counter"], "provider_rules": document["contact_rulebook"],
            "receiver_rules": copy.deepcopy(receiver.contact_rulebook),
            "receiver_otks": sorted(digest(k) for k in receiver.otks_dict),
            "active_tokens": {digest(k.encode()): copy.deepcopy(v) for k, v in receiver.active_tokens.items()}}


def run_case(case, provider, initiator, receiver, recorder, artifact):
    checks = artifact.setdefault("assertions", [])

    def check(name, expected, actual):
        checks.append({"name": name, "expected": expected, "actual": actual,
                       "status": "pass" if expected == actual else "fail",
                       "through_event": len(recorder.events)})

    context = {"initiator": INITIATOR, "target": INITIATOR, "receiver": RECEIVER,
               "receiver_binding": "observed fixture owner in this consumer execution",
               "rules": [{"id": f"r{i}", "position": i, **r} for i, r in enumerate(case["rules"])]}
    context["policy_hash"] = policy_hash(context)
    spec = evaluate(context)
    artifact["input"] = {"context": context, "evaluation_fingerprint": fingerprint(context),
                         "spec": spec, "case": case, "q_max": saga.config.Q_MAX,
                         "initiator_cert_sha256": digest(pem(initiator.cert)),
                         "receiver_cert_sha256": digest(pem(receiver.cert))}
    artifact["before"] = snapshot(provider, receiver)
    check("supported_spec", "OK", spec["status"])
    check("spec_budget", case["spec_budget"], spec.get("budget"))
    check("provider_rules", case["rules"], artifact["before"]["provider_rules"])
    check("receiver_rules", case["rules"], artifact["before"]["receiver_rules"])
    check("initial_counter", [], artifact["before"]["counter"])
    check("initial_active_tokens", {}, artifact["before"]["active_tokens"])
    check("initial_otk_count", 1, len(artifact["before"]["provider_otks"]))
    check("initial_otk_binding", artifact["before"]["provider_otks"], artifact["before"]["receiver_otks"])
    cutoff_calls = []
    connection = None

    def cutoff(agent, conn, token, recipient_pac):
        # The real handler reads these monitors after the boundary returns.
        # Empty timing records allow that epilogue; no conversation code is run.
        cutoff_calls.append(token)
        recorder.add("conversation_boundary", token_sha256=digest(token.encode()),
                     token_stored=token in agent.active_tokens,
                     token_sent=bool(conn.sent and conn.sent[-1].get("token") == token))
        for monitor, name in ((agent.monitor, "agent:communication_conv_recv"),
                              (agent.llm_monitor, "agent:llm_backend_recv")):
            monitor.start(name)
            monitor.stop(name)

    original = policy.match
    with patch("saga.provider.provider.match", recorder.matcher("provider", original)), \
         patch("saga.agent.match", recorder.matcher("receiver", original)), \
         patch.object(Agent, "receive_conversation", cutoff):
        response = provider.app.test_client().post("/access", json={"i_aid": INITIATOR, "t_aid": RECEIVER},
                         environ_overrides={"SSL_CLIENT_CERT": pem(initiator.cert).decode()})
        body = bson.json_util.loads(response.get_data(as_text=True))
        artifact["http"] = {"status": response.status_code, "body": json.loads(response.get_data(as_text=True)),
                            "raw_body": response.get_data(as_text=True)}
        recorder.add("provider_response", status=response.status_code,
                     response_sha256=digest(response.data),
                     otk_sha256=[digest(bytes(k)) for k in body.get("one_time_keys", [])])
        allowed = case["impl_budget"] > 0
        check("http_status", 200 if allowed else 403, response.status_code)
        if response.status_code == 200:
            otks = body["one_time_keys"]
            check("released_otk_count", 1, len(otks))
            check("response_receiver", RECEIVER, body.get("aid"))
            released = bytes(otks[0])
            check("released_otk_binding", artifact["before"]["provider_otks"], [digest(released)])
            recorder.add("otk_release", status="observed", otk_sha256=digest(released))
            handshake = {"card": copy.deepcopy(initiator.card), "stamp": initiator.stamp,
                         "crt_u": b64(pem(initiator.crt_u)), "otk": b64(released)}
            artifact["handshake"] = handshake
            recorder.add("receiver_handshake", initiator=INITIATOR, receiver=RECEIVER,
                         otk_sha256=digest(released))
            connection = MemoryConnection(handshake, initiator.cert.public_bytes(sc.serialization.Encoding.DER), recorder)
            receiver.handle_i_agent_connection(connection, ("127.0.0.1", 23456))
            check("exactly_one_token_response", 1, len(connection.sent))
            if connection.sent:
                token = connection.sent[0].get("token")
                check("token_response_shape", ["token"], sorted(connection.sent[0]))
                check("active_token_binding", True, token in receiver.active_tokens)
                dh = initiator.sac.exchange(sc.bytesToPublicX25519Key(released))
                shared = sc.HKDF(algorithm=sc.hashes.SHA256(), length=32, salt=None,
                                 info=b"access-control-shdk-exchange").derive(dh)
                decoded = sc.decrypt_token(token, shared)
                artifact["token"] = {"sha256": digest(token.encode()), "decoded": decoded}
                check("token_decryption_matches_storage", decoded, receiver.active_tokens.get(token))
                check("token_pac", b64(raw_public(initiator.pac)), decoded["recipient_pac"])
                check("token_initial_quota", saga.config.Q_MAX, decoded["communication_quota"])
                check("token_valid_time", True, datetime.fromisoformat(decoded["issue_timestamp"]) <=
                      datetime.now(timezone.utc) < datetime.fromisoformat(decoded["expiration_timestamp"]))
                recorder.add("token_issuance_checked", token_sha256=digest(token.encode()),
                             stored=token in receiver.active_tokens, decrypted=True)
        elif response.status_code == 403:
            for stage in ("otk_release", "receiver_handshake", "token_issuance"):
                recorder.add(stage, status="not_reached", reason="provider_denied")
        artifact["after"] = snapshot(provider, receiver)
        check("cutoff_count", 1 if allowed else 0, len(cutoff_calls))
        for event in recorder.events:
            if event["stage"] == "conversation_boundary":
                check("stored_before_cutoff", True, event["token_stored"])
                check("sent_before_cutoff", True, event["token_sent"])
        matches = [e for e in recorder.events if e["stage"] == "matcher"]
        check("matcher_consumers", ["provider", "receiver"] if allowed else ["provider"],
              [e["consumer"] for e in matches])
        for event in matches:
            check(event["consumer"] + "_matcher_input", [case["rules"], INITIATOR], [event["rules"], event["target"]])
            check(event["consumer"] + "_matcher_budget", case["impl_budget"], event.get("budget"))
        check("local_agent_run_count", 0, receiver.local_agent.calls + initiator.local_agent.calls)
        check("conversation_reads", 0, connection.extra_reads if connection else 0)
        if allowed:
            check("provider_otks_consumed", [], artifact["after"]["provider_otks"])
            check("provider_otk_sigs_consumed", [], artifact["after"]["provider_otk_sigs"])
            check("provider_counter", [{"aid": INITIATOR, "budget": case["impl_budget"] - 1}], artifact["after"]["counter"])
            check("receiver_otks_consumed", [], artifact["after"]["receiver_otks"])
            check("active_token_count", 1, len(artifact["after"]["active_tokens"]))
            check("connection_closed", True, connection.closed if connection else False)
        else:
            check("denial_state_unchanged", artifact["before"], artifact["after"])
    return all(c["status"] == "pass" for c in checks)
