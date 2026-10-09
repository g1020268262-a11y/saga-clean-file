import copy
import unittest
from unittest.mock import patch
import json
from bridge import (ROOT, ARCHIVE, read, digest, make_context, build, evaluate,
                    generate, policy_hash, write_json, verify_historical_source, current_source_state, SOURCE, MODEL,
                    export_context_metadata)
from generate_model import (derive_model, reconstruct, split_template, normalize_comments,
                            validate_structure, COMMENT_NORMALIZATIONS)
from run_verification import summarize
import tempfile
from pathlib import Path

CONTROLS = "proofs/decision_bridge/observations/20260922T064049858703Z"


def historical(reverse=False):
    data = read(ARCHIVE)
    context = make_context(list(reversed(data["rules"])) if reverse else data["rules"], data["aid"],
                           data["source_sha256"], data["base_commit"], "stage1-alice")
    reference = {"path": ARCHIVE, "sha256": digest((ROOT / ARCHIVE).read_bytes()), "format": "stage1",
                 "field": "actual_wildcard_allow_then_specific_deny" if reverse else "actual_specific_deny_then_wildcard_allow"}
    return context, reference


class BridgeTests(unittest.TestCase):
    def test_provenance_export_preserves_archived_pair(self):
        archive = "proofs/evidence/authz-bridge-turepass-20260922T111657792091Z/"
        inputs = read(archive + "input.json")
        archived = read(archive + "bridge-result.json")
        result = build(inputs["context"], inputs["observation"])
        self.assertEqual(result, archived)
        before = json.dumps(result)
        metadata = export_context_metadata(result)
        self.assertEqual(json.dumps(result), before)
        self.assertEqual(build(inputs["context"], inputs["observation"]), archived)
        # Exported nested provenance must not alias the legacy pair.
        metadata["provenance"]["observation"]["sha256"] = "0" * 64
        self.assertEqual(json.dumps(result), before)

    def test_provenance_metadata_from_existing_evidence(self):
        result = build(*historical())
        metadata = export_context_metadata(result)
        self.assertEqual(set(metadata), {"context_id", "policy_id", "policy_version", "policy_hash",
                                        "subject", "target", "evaluation_fingerprint", "provenance"})
        for field in ("policy_id", "policy_version", "policy_hash", "target"):
            self.assertEqual(metadata[field], result["context"][field])
        self.assertEqual(metadata["subject"], result["context"]["initiator"])
        self.assertEqual(metadata["evaluation_fingerprint"], result["evaluation_fingerprint"])
        self.assertEqual(metadata["provenance"], {
            "observation": result["impl_observed"]["observation"],
            "historical_source": result["impl_observed"]["historical_source"],
            "generator_version": result["generator_version"],
        })
        self.assertRegex(metadata["context_id"], r"^analysis-context-sha256:[0-9a-f]{64}$")
        # Record-content identity only: JSON key ordering is not new evidence.
        self.assertEqual(metadata, export_context_metadata(json.loads(json.dumps(result, sort_keys=True))))

    def test_different_policy_hashes_have_different_record_fingerprints(self):
        # Different evidence records, not a claim about authorization events.
        forward, reverse = (export_context_metadata(build(*historical(value))) for value in (False, True))
        self.assertNotEqual(forward["policy_hash"], reverse["policy_hash"])
        self.assertNotEqual(forward["context_id"], reverse["context_id"])

    def test_record_fingerprint_does_not_identify_an_execution(self):
        """Only analysis record identity is represented, never event identity."""
        first = build(*historical())
        replay = build(*historical())
        self.assertIsNot(first, replay)
        # Separate analyses of identical evidence intentionally share a fingerprint.
        self.assertEqual(export_context_metadata(first)["context_id"],
                         export_context_metadata(replay)["context_id"])
        context, reference = historical()
        context["policy_id"] += "-analysis-label-test"
        relabeled = build(context, reference)
        # A test-only analysis label changes the record, without a new observation
        # or new decisions. Neither equal nor unequal IDs identify real events.
        self.assertEqual(first["spec"], relabeled["spec"])
        self.assertEqual(first["impl_observed"], relabeled["impl_observed"])
        self.assertEqual(first["divergence"], relabeled["divergence"])
        self.assertNotEqual(export_context_metadata(first)["context_id"],
                            export_context_metadata(relabeled)["context_id"])

    def test_provenance_export_rejects_changed_evidence_reference(self):
        base = build(*historical())
        for section, field in (("observation", "sha256"),
                               ("historical_source", "historical_git_blob_sha256")):
            with self.subTest(section=section):
                result = copy.deepcopy(base)
                result["impl_observed"][section][field] = "0" * 64
                with self.assertRaises(ValueError):
                    export_context_metadata(result)
        result = copy.deepcopy(base)
        result["evaluation_fingerprint"] = "0" * 64
        with self.assertRaises(ValueError):
            export_context_metadata(result)

    def test_provenance_export_rejects_missing_provenance(self):
        base = build(*historical())
        paths = [("generator_version",),
                 ("context", "source"), ("context", "source_sha256"), ("context", "source_commit"),
                 ("impl_observed", "observation"), ("impl_observed", "historical_source")]
        for field in base["impl_observed"]["observation"]:
            paths.append(("impl_observed", "observation", field))
        for field in base["impl_observed"]["historical_source"]:
            paths.append(("impl_observed", "historical_source", field))
        for path in paths:
            with self.subTest(path=path):
                result = copy.deepcopy(base)
                parent = result
                for key in path[:-1]:
                    parent = parent[key]
                del parent[path[-1]]
                with self.assertRaisesRegex(ValueError, "provenance"):
                    export_context_metadata(result)

    def test_provenance_export_rejects_tampered_pair(self):
        for section, field, value in (("spec", "decision", "Allow"),
                                      ("impl_observed", "decision", "Deny"),
                                      ("context", "policy_hash", "0" * 64)):
            with self.subTest(section=section, field=field):
                result = build(*historical())
                result[section][field] = value
                with self.assertRaises(ValueError):
                    export_context_metadata(result)
        result = build(*historical())
        result["divergence"] = False
        with self.assertRaises(ValueError):
            export_context_metadata(result)
        for result in ({"status": "Unsupported"}, {"status": "Invalid"}, None):
            with self.assertRaisesRegex(ValueError, "OK decision pair"):
                export_context_metadata(result)

    def test_historical_replay_does_not_require_current_source_match(self):
        real_read = Path.read_bytes
        def changed_current(path):
            return b"hypothetical later matcher repair\n" if path == ROOT / SOURCE else real_read(path)
        context, ref = historical()
        with patch.object(Path, "read_bytes", changed_current):
            result = build(context, ref)
            self.assertTrue(result["divergence"])
            self.assertFalse(current_source_state(context["source_sha256"])["current_source_matches_historical"])

    def test_missing_historical_commit(self):
        with self.assertRaises(ValueError):
            verify_historical_source("0" * 40, "0" * 64)

    def test_wrong_historical_blob(self):
        context, _ = historical()
        with patch("bridge.git", return_value=b"unrelated historical contents\n"):
            with self.assertRaises(ValueError):
                verify_historical_source(context["source_commit"], context["source_sha256"])

    def test_explicit_eol_verification(self):
        with patch("bridge.git", return_value=b"a\nb\n"):
            binding = verify_historical_source("1" * 40, digest(b"a\r\nb\r\n"))
            self.assertEqual(binding["verified_byte_encoding"], "uniform-CRLF")
            self.assertNotEqual(binding["historical_git_blob_sha256"], binding["archived_source_byte_sha256"])
            with self.assertRaises(ValueError):
                verify_historical_source("1" * 40, digest(b"a\r\nb\n"))

    def test_full_model_preserves_source(self):
        data = json.dumps(build(*historical())).encode()
        generated = derive_model(data)
        header, body = generated.split(b"*)\n", 1)
        self.assertEqual(body, normalize_comments((ROOT / MODEL).read_bytes()))
        self.assertIn(digest(data).encode(), header)

    def test_scenario_reconstructed_from_validated_generator(self):
        result = build(*historical())
        # Instrument the validated generator's output with harmless whitespace.
        # The new body must consume it rather than retain the source block.
        fragment = generate(result).replace("insert Scenario", "insert  Scenario")
        with patch("generate_model.generate", return_value=fragment) as generator:
            _, body, block = reconstruct(json.dumps(result).encode())
            generator.assert_called_once_with(result)
        self.assertIn(b"insert  ScenarioSpecDeny", block)
        self.assertIn(block, body)
        self.assertNotIn(b"  insert ScenarioSpecDeny(BuggyPolicy, aid_B);", body)

    def test_nondivergent_pair_cannot_generate_full_model(self):
        with self.assertRaises(ValueError):
            derive_model(json.dumps(build(*historical(True))).encode())

    def test_scenario_region_must_be_unique(self):
        source = (ROOT / MODEL).read_bytes()
        prefix, suffix, _ = split_template(source)
        block = source[len(prefix):len(source)-len(suffix)]
        for mutated in (source + block, prefix + suffix):
            with self.subTest(kind="duplicate" if mutated.endswith(block) else "missing"):
                with self.assertRaises(ValueError):
                    split_template(mutated)

    def test_structure_rejects_protocol_mutations(self):
        _, body, block = reconstruct(json.dumps(build(*historical())).encode())
        source = (ROOT / MODEL).read_bytes()
        mutations = {
            "query": (b"==> event(TokenIssue", b"==> event(TokenReceive"),
            "event": (b"event ChatAccept(bitstring", b"event ChangedAccept(bitstring"),
            "process": (b"if sender = aid_B then", b"if sender = aid_A then"),
            "channel": (b"free tls_chat: channel [private].", b"free tls_chat: channel."),
            "token": (b"new token: bitstring;", b"let token = BuggyPolicy in"),
        }
        for kind, (old, new) in mutations.items():
            with self.subTest(kind=kind):
                self.assertIn(old, body)
                with self.assertRaises(ValueError):
                    validate_structure(body.replace(old, new, 1), source, block)
        with self.assertRaises(ValueError):
            validate_structure(body + b"\nevent start();\n", source, block)

    def test_only_approved_comment_changes(self):
        _, body, block = reconstruct(json.dumps(build(*historical())).encode())
        source = (ROOT / MODEL).read_bytes()
        for old, new in COMMENT_NORMALIZATIONS:
            self.assertNotIn(old.encode(), body)
            self.assertIn(new.encode(), body)
        with self.assertRaises(ValueError):
            validate_structure(body + b"(* unapproved extra comment *)", source, block)

    def test_full_model_rejects_tampered_pair(self):
        result = build(*historical())
        result["impl_observed"]["budget"] = -1
        with self.assertRaises(ValueError):
            derive_model(json.dumps(result).encode())

    def test_frozen_template_check(self):
        data = json.dumps(build(*historical())).encode()
        with patch("generate_model.TEMPLATE_SHA256", "0" * 64):
            with self.assertRaises(ValueError):
                derive_model(data)

    def test_result_parser_not_missing_or_unknown(self):
        # Parser fixtures only; these are NOT verifier evidence.
        output = ("RESULT event(ChatAccept(r,s,t,m)) ==> event(TokenIssue(r,s,t)) is true.\n"
                  "RESULT not event(ChatAccept(r,s,t,m)) is false.\n")
        self.assertTrue(summarize(output)["chat_accept_reachable"])
        self.assertTrue(summarize(output)["chat_accept_implies_token_issue"])
        self.assertTrue(summarize(output)["expected_query_set"])
        self.assertFalse(summarize("")["expected_query_set"])
        self.assertFalse(summarize(output.replace(" is false.", " cannot be proved."))["chat_accept_reachable"])

    def test_real_counterexample(self):
        result = build(*historical())
        self.assertEqual(result["spec"]["budget"], -1)
        self.assertEqual(result["spec"]["specificity"], 70)
        self.assertEqual(result["impl_observed"]["budget"], 10)
        self.assertTrue(result["divergence"])
        self.assertIn("insert ScenarioImplAllow(BuggyPolicy, aid_B);", generate(result))

    def test_reverse(self):
        result = build(*historical(True))
        self.assertEqual(result["spec"]["decision"], "Deny")
        self.assertEqual(result["impl_observed"]["decision"], "Deny")
        self.assertFalse(result["divergence"])
        self.assertIsNone(generate(result))

    def control(self, name, decision):
        path = CONTROLS + "/" + name + ".json"
        data = read(path)
        context = make_context(data["rules"], data["aid"], data["source_sha256"], data["base_commit"], name)
        result = build(context, {"path": path, "sha256": digest((ROOT / path).read_bytes()), "format": "bridge-observation-v1"})
        self.assertEqual(result["spec"]["decision"], decision)
        self.assertEqual(result["impl_observed"]["decision"], decision)
        self.assertFalse(result["divergence"])
        self.assertIsNone(generate(result))

    def test_normal_allow(self):
        self.control("allow", "Allow")

    def test_normal_deny(self):
        self.control("deny", "Deny")

    def test_unsupported_even_when_nonmatching(self):
        context, ref = historical()
        for pattern in ("bob@*.com:*", "alice@example.com:a?ent", "alice@example.com:[a-z]", "Alice@example.com:*"):
            with self.subTest(pattern=pattern):
                context["rules"][0]["pattern"] = pattern
                self.assertEqual(build(context, ref)["status"], "Unsupported")

    def test_tie(self):
        context, _ = historical()
        context["rules"][1]["pattern"] = context["rules"][0]["pattern"]
        self.assertEqual(evaluate(context)["status"], "Unsupported")

    def test_invalid(self):
        base, _ = historical()
        for field, value in (("budget", True), ("budget", -2), ("position", 1), ("pattern", None)):
            context = copy.deepcopy(base)
            context["rules"][0][field] = value
            self.assertEqual(evaluate(context)["status"], "Invalid")
        self.assertEqual(evaluate({})["status"], "Invalid")

    def test_zero_no_match_and_exact(self):
        context, _ = historical()
        for rules, budget in (([], 0), ([{"pattern": "bob@example.com:*", "budget": 10}], 0),
                              ([{"pattern": "*", "budget": 0}], 0),
                              ([{"pattern": "alice@example.com:agent", "budget": 10}], 10)):
            context["rules"] = [{"id": str(i), "position": i, **r} for i, r in enumerate(rules)]
            self.assertEqual(evaluate(context)["budget"], budget)

    def test_context_mismatch(self):
        for field, value in (("target", "bob@example.com:agent"), ("source_sha256", "0" * 64),
                              ("policy_hash", "0" * 64), ("source_commit", "0" * 40), ("receiver", "aid_B")):
            context, ref = historical()
            context[field] = value
            with self.assertRaises(ValueError):
                build(context, ref)
        context, ref = historical(True)
        ref["field"] = "actual_specific_deny_then_wildcard_allow"
        with self.assertRaises(ValueError):
            build(context, ref)

    def test_archive_hash_and_expected_rejected(self):
        context, ref = historical()
        ref["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            build(context, ref)
        context, ref = historical()
        ref["field"] = "expected_under_documented_most_specific_semantics"
        with self.assertRaises(ValueError):
            build(context, ref)

    def test_generator_recomputes(self):
        result = build(*historical())
        result["spec"]["decision"] = "Allow"
        with self.assertRaises(ValueError):
            generate(result)

    def test_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact.json"
            write_json(path, {"original": True})
            with self.assertRaises(FileExistsError):
                write_json(path, {})


if __name__ == "__main__":
    unittest.main()
