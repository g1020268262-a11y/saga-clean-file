"""Harness integrity tests, independent of mongod and of expected consumer outcomes."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from saga.agent import Agent
from saga.common.contact_policy import match
from proofs.consumer_validation.fixtures import ForbiddenLocalAgent
from proofs.consumer_validation.harness import Recorder, MemoryConnection
from proofs.consumer_validation.run_phase1 import HERE, new_archive, write_json, redact


class HarnessTests(unittest.TestCase):
    def test_spy_preserves_real_result_and_order(self):
        rules = [{"pattern": "alice@example.com:*", "budget": -1}, {"pattern": "*", "budget": 10}]
        before = copy.deepcopy(rules)
        recorder = Recorder("test")
        result = recorder.matcher("provider", match)(rules, "alice@example.com:agent")
        self.assertEqual(result, 10)
        self.assertEqual(rules, before)
        rules.reverse()
        self.assertEqual(recorder.events[0]["rules"], before)
        self.assertEqual(recorder.matcher("receiver", match)(rules, "alice@example.com:agent"), -1)

    def test_spy_preserves_exception(self):
        recorder = Recorder("test")
        error = ValueError("sentinel")
        def raising(*args):
            raise error
        with self.assertRaises(ValueError) as caught:
            recorder.matcher("receiver", raising)([], "alice@example.com:agent")
        self.assertIs(caught.exception, error)
        self.assertEqual(recorder.events[0]["status"], "error")

    def test_production_framing_roundtrip(self):
        recorder = Recorder("test")
        payload = {"otk": "fixture", "card": {"aid": "alice@example.com:agent"}}
        conn = MemoryConnection(payload, b"der", recorder)
        self.assertEqual(Agent.recv(None, conn), payload)
        Agent.send(None, conn, {"token": "test-token"})
        self.assertEqual(conn.sent, [{"token": "test-token"}])
        self.assertEqual(conn.getpeercert(True), b"der")

    def test_conversation_reads_fail(self):
        conn = MemoryConnection({}, b"der", Recorder("test"))
        Agent.recv(None, conn)
        with self.assertRaises(AssertionError):
            conn.recv(4)
        self.assertEqual(conn.extra_reads, 1)

    def test_backend_is_forbidden_and_counted(self):
        backend = ForbiddenLocalAgent()
        with self.assertRaises(AssertionError):
            backend.run("must not run")
        self.assertEqual(backend.calls, 1)

    def test_archive_cannot_be_overwritten_or_escape(self):
        runtime = HERE / ".runtime"
        runtime.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=runtime) as tmp, patch("proofs.consumer_validation.run_phase1.HERE", Path(tmp)):
            dest = new_archive("one")
            write_json(dest / "result.json", {"original": True})
            with self.assertRaises(FileExistsError):
                new_archive("one")
            with self.assertRaises(FileExistsError):
                write_json(dest / "result.json", {"original": False})
            with self.assertRaises(ValueError):
                new_archive("../escape")
            self.assertEqual(json.loads((dest / "result.json").read_text()), {"original": True})

    def test_secrets_are_removed_from_logs(self):
        output = redact("Derived SDHK: abcdef\nGenerated token: secret\nordinary\n")
        self.assertNotIn("abcdef", output)
        self.assertNotIn("secret", output)
        self.assertIn("ordinary", output)

    def test_serialization_failure_does_not_leave_partial_file(self):
        runtime = HERE / ".runtime"
        runtime.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=runtime) as tmp:
            path = Path(tmp) / "result.json"
            with self.assertRaises(TypeError):
                write_json(path, {"not_json": b"bytes"})
            self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
