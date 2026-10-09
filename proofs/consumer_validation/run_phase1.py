"""Run the three Phase 1 cases and retain immutable, bounded execution evidence."""
import argparse
from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import io
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import traceback
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.dont_write_bytecode = True
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

VERSION = "consumer-phase1-1"
MOCKS = ["Flask test_client supplies fixture SSL_CLIENT_CERT (no TLS handshake)",
         "CA download constructor replaced by locally generated CA; sign/verify remain real",
         "Agent.get_provider_cert returns local Provider certificate",
         "Registration records seeded directly with real signed material",
         "MemoryConnection replaces receiver TLS socket; Agent.send/recv remain real",
         "Agent.receive_conversation records boundary and empty timings, then returns",
         "ForbiddenLocalAgent.run counts calls and raises; never expected to execute"]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def sources():
    files = list((ROOT / "saga").rglob("*.py"))
    files += list((ROOT / "agent_backend").glob("*.py"))
    files += list(HERE.glob("*.py"))
    files += [ROOT / "proofs/decision_bridge/bridge.py", ROOT / "config.yaml",
              HERE / "cases.json", HERE / "requirements.txt", HERE / "README.md"]
    return {p.relative_to(ROOT).as_posix(): sha(p) for p in sorted(files)}


def write_json(path, value):
    encoded = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(encoded)


def write_text(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(value)


def new_archive(name=None):
    base = HERE / "evidence"
    base.mkdir(exist_ok=True)
    if name is None:
        name = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex[:8]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,100}", name):
        raise ValueError("Archive name must be a simple directory name")
    destination = base / name
    destination.mkdir(exist_ok=False)
    return destination


def redact(text):
    text = re.sub(r"\x1b\[[0-9;]*m", "", text)
    text = re.sub(r"(Derived SDHK: )[^\r\n]+", r"\1[REDACTED]", text)
    return re.sub(r"(Generated token: )[^\r\n]+", r"\1[REDACTED]", text)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mongod", required=True, type=Path, help="Local mongod executable (a fresh isolated process is started)")
    parser.add_argument("--archive-name", help="Optional new directory name under consumer_validation/evidence")
    args = parser.parse_args(argv)
    dest = new_archive(args.archive_name)
    manifest = {"schema_version": 1, "harness_version": VERSION, "run_id": dest.name,
                "started_utc": datetime.now(timezone.utc).isoformat(),
                "scope": "token_issuance_only", "message_acceptance": "not_executed",
                "git_head": git("rev-parse", "HEAD"), "git_status_before": git("status", "--short"),
                "python": platform.python_version(), "platform": platform.platform(),
                "command": ["python", "-B", "proofs/consumer_validation/run_phase1.py",
                            "--mongod", args.mongod.name] + (["--archive-name", args.archive_name] if args.archive_name else []),
                "command_paths": "Executable paths represented by basename; see executable hash",
                "mocks": MOCKS, "source_sha256_before": sources(),
                "redactions": ["ANSI escapes removed", "Derived SDHK and Generated token log values removed"],
                "cases": [], "execution_status": "error", "expectations_met": False,
                "dependencies": dict(sorted((d.metadata["Name"], d.version) for d in importlib.metadata.distributions()))}
    write_json(dest / "run-start.json", manifest)
    # Preserve exact text bytes through Git, including JSON and logs.
    write_text(dest / ".gitattributes", "* -text\n")
    out, err = io.StringIO(), io.StringIO()
    try:
        with redirect_stdout(out), redirect_stderr(err):
            from proofs.consumer_validation.fixtures import isolated_mongo, fixture
            from proofs.consumer_validation.harness import Recorder, run_case
            manifest["mongod_sha256"] = sha(args.mongod)
            env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
            test_command = [sys.executable, "-B", "-m", "unittest", "proofs.consumer_validation.test_harness", "-v"]
            tested = subprocess.run(test_command, cwd=ROOT, capture_output=True, text=True, env=env, timeout=60)
            write_text(dest / "tests-stdout.txt", redact(tested.stdout))
            write_text(dest / "tests-stderr.txt", redact(tested.stderr))
            manifest["tests"] = {"command": ["python", *test_command[1:]], "exit_code": tested.returncode}
            if tested.returncode:
                raise RuntimeError("Harness tests failed; consumer experiments not started")
            cases = json.loads((HERE / "cases.json").read_text())
            with isolated_mongo(args.mongod) as (uri, mongo_version):
                manifest["mongodb_version"] = mongo_version
                for case in cases:
                    case_dir = dest / "cases" / case["id"]
                    case_dir.mkdir(parents=True)
                    recorder = Recorder(case["id"])
                    result = {"case_id": case["id"], "pair": case["pair"], "execution_status": "error"}
                    try:
                        with fixture(uri, case) as (provider, initiator, receiver):
                            passed = run_case(case, provider, initiator, receiver, recorder, result)
                        result["execution_status"] = "completed"
                        result["expectations_met"] = passed
                    except Exception as exc:
                        result["expectations_met"] = False
                        result["error"] = {"type": type(exc).__name__, "message": str(exc)}
                        traceback.print_exc()
                    finally:
                        input_data = result.pop("input", {"case": case, "status": "initialization_failed"})
                        write_json(case_dir / "input.json", input_data)
                        write_json(case_dir / "result.json", result)
                        write_text(case_dir / "events.jsonl", "".join(json.dumps(e, sort_keys=True) + "\n" for e in recorder.events))
                        manifest["cases"].append({k: result[k] for k in ("case_id", "pair", "execution_status", "expectations_met")})
            manifest["execution_status"] = "completed" if all(c["execution_status"] == "completed" for c in manifest["cases"]) else "error"
            manifest["expectations_met"] = len(manifest["cases"]) == 3 and all(c["expectations_met"] for c in manifest["cases"])
    except Exception as exc:
        manifest["error"] = {"type": type(exc).__name__, "message": str(exc)}
        traceback.print_exc(file=err)
    finally:
        write_text(dest / "stdout.txt", redact(out.getvalue()))
        write_text(dest / "stderr.txt", redact(err.getvalue()))
        manifest["source_sha256_after"] = sources()
        manifest["sources_unchanged"] = manifest["source_sha256_before"] == manifest["source_sha256_after"]
        manifest["expectations_met"] = manifest["expectations_met"] and manifest["sources_unchanged"]
        manifest["finished_utc"] = datetime.now(timezone.utc).isoformat()
        manifest["git_status_after"] = git("status", "--short")
        manifest["exit_code"] = 0 if manifest["expectations_met"] else 1
        summary = ["Phase 1 consumer propagation validation", "Scope: token issuance only; no message acceptance."]
        summary += [f"{c['pair']}: {c['execution_status']}; expectations_met={c['expectations_met']}" for c in manifest["cases"]]
        summary += ["TLS/registration/application execution not validated. No deployment exploit claim.",
                    f"Exit code: {manifest['exit_code']}"]
        write_text(dest / "summary.txt", "\n".join(summary) + "\n")
        manifest["artifact_sha256"] = {p.relative_to(dest).as_posix(): sha(p) for p in sorted(dest.rglob("*")) if p.is_file()}
        write_json(dest / "manifest.json", manifest)
    print(f"Evidence: {dest}")
    print("\n".join(summary))
    return manifest["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
