"""Isolated resources; production initialization and cryptographic checks stay real."""
import base64
import copy
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
from contextlib import contextmanager, ExitStack
from unittest.mock import patch

from pymongo import MongoClient
import saga.common.crypto as sc
from saga.ca.CA import CA
from saga.local_agent import LocalAgent
from saga.agent import Agent
from saga.provider.provider import Provider

HERE = Path(__file__).resolve().parent
INITIATOR = "alice@example.com:agent"
RECEIVER = "bob@example.com:receiver"


def b64(value):
    return base64.b64encode(value).decode("ascii")


def raw_public(key):
    return key.public_bytes(sc.serialization.Encoding.Raw, sc.serialization.PublicFormat.Raw)


def raw_private(key):
    return key.private_bytes(sc.serialization.Encoding.Raw, sc.serialization.PrivateFormat.Raw,
                             sc.serialization.NoEncryption())


def pem(cert):
    return cert.public_bytes(sc.serialization.Encoding.PEM)


class ForbiddenLocalAgent(LocalAgent):
    task_finished_token = "<TASK_FINISHED>"

    def __init__(self):
        self.calls = 0

    def run(self, *args, **kwargs):
        self.calls += 1
        raise AssertionError("Phase 1 must never execute local_agent.run")


@contextmanager
def isolated_mongo(executable):
    """Start only our own loopback mongod; never attach to an existing database."""
    runtime = HERE / ".runtime"
    runtime.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mongo-", dir=runtime) as tmp:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        command = [str(Path(executable).resolve()), "--bind_ip", "127.0.0.1",
                   "--port", str(port), "--dbpath", tmp, "--logpath", str(Path(tmp) / "mongod.log")]
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        client = MongoClient(f"mongodb://127.0.0.1:{port}", serverSelectionTimeoutMS=500)
        try:
            deadline = time.monotonic() + 30
            while True:
                if process.poll() is not None:
                    raise RuntimeError("Isolated mongod exited during startup")
                try:
                    info = client.server_info()
                    server_path = client.admin.command("getCmdLineOpts")["parsed"]["storage"]["dbPath"]
                    if Path(server_path).resolve() != Path(tmp).resolve():
                        raise RuntimeError("Loopback MongoDB does not belong to this runner")
                    break
                except Exception:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("Isolated mongod startup timed out")
                    time.sleep(0.1)
            yield f"mongodb://127.0.0.1:{port}", info["version"]
        finally:
            client.close()
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)


def make_ca():
    # Bypass only CA's downloader constructor; retain production sign/verify methods.
    ca = CA.__new__(CA)
    ca.private_key, ca.public_key = sc.generate_ed25519_keypair()
    config = {"COUNTRY_NAME": "US", "STATE_OR_PROVINCE_NAME": "Test",
              "LOCALITY_NAME": "Test", "ORGANIZATION_NAME": "Phase1",
              "COMMON_NAME": "phase1-ca", "IP": "127.0.0.1"}
    ca.cert = sc.generate_self_signed_x509_certificate(config, ca.private_key, ca.public_key)
    return ca


def make_material(aid, rules, ca, provider):
    user_sk, user_pk = sc.generate_ed25519_keypair()
    user_cert = ca.sign(user_pk, {"COMMON_NAME": aid.split(":")[0]})
    agent_sk, agent_pk = sc.generate_ed25519_keypair()
    agent_cert = ca.sign(agent_pk, {"COMMON_NAME": aid})
    sac, pac = sc.generate_x25519_keypair()
    sotk, otk = sc.generate_x25519_keypair()
    network = {"aid": aid, "device": "phase1", "IP": "127.0.0.1", "port": 12345}
    block = {**network, "pk_a": raw_public(agent_pk), "pac": raw_public(pac),
             "pk_prov": raw_public(provider.PK_Prov)}
    agent_sig = user_sk.sign(str(block).encode())
    card = {**network, "agent_cert": pem(agent_cert), "pac": raw_public(pac), "agent_sig": agent_sig}
    material = {**network, "secret_signing_key": b64(raw_private(agent_sk)),
                "agent_cert": b64(pem(agent_cert)), "pac": b64(raw_public(pac)),
                "sac": b64(raw_private(sac)), "sotks": [b64(raw_private(sotk))],
                "otks": [b64(raw_public(otk))], "contact_rulebook": copy.deepcopy(rules),
                "agent_sig": b64(agent_sig), "stamp": b64(provider.SK_Prov.sign(str(card).encode())),
                "crt_u": b64(pem(user_cert))}
    record = {**card, "one_time_keys": [raw_public(otk)],
              "one_time_key_sigs": [user_sk.sign(raw_public(otk))],
              "contact_rulebook": copy.deepcopy(rules), "counter": []}
    user = {"uid": aid.split(":")[0], "crt_u": pem(user_cert)}
    return material, record, user


@contextmanager
def fixture(uri, case):
    with tempfile.TemporaryDirectory(prefix="keys-", dir=HERE / ".runtime") as tmp, ExitStack() as stack:
        ca = make_ca()
        stack.enter_context(patch("saga.provider.provider.get_SAGA_CA", return_value=ca))
        stack.enter_context(patch("saga.agent.get_SAGA_CA", return_value=ca))
        provider = Provider(str(Path(tmp) / "provider"), "provider",
                            mongo_uri=f"{uri}/phase1_{case['id']}")
        stack.callback(provider.mongo.cx.close)
        provider.app.config["TESTING"] = True
        stack.enter_context(patch.object(Agent, "get_provider_cert", return_value=provider.cert))
        agents = []
        for aid in (INITIATOR, RECEIVER):
            material, record, user = make_material(aid, case["rules"], ca, provider)
            provider.users_collection.insert_one(user)
            provider.agents_collection.insert_one(record)
            directory = Path(tmp) / aid.split(":")[1]
            directory.mkdir()
            agents.append(Agent(str(directory), material, ForbiddenLocalAgent()))
        yield provider, agents[0], agents[1]
