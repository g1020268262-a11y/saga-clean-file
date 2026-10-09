"""Clean-commit generation and actual ProVerif execution; append-only evidence."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

from bridge import ROOT, MODEL, VERSION, build, current_source_state, digest, git, write_json
from generate_model import derive_model, reconstruct, TEMPLATE_SHA256
from run_bridge import default_input


def summarize(stdout):
    results = [line.strip() for line in stdout.splitlines() if line.startswith("RESULT ")]
    correspondence = [r for r in results if "event(ChatAccept(" in r and "==> event(TokenIssue(" in r]
    reachability = [r for r in results if r.startswith("RESULT not event(ChatAccept(")]
    return {"raw_results": results,
            "chat_accept_reachable": len(reachability) == 1 and reachability[0].endswith(" is false."),
            "chat_accept_implies_token_issue": len(correspondence) == 1 and correspondence[0].endswith(" is true."),
            "expected_query_set": len(results) == 2 and len(correspondence) == len(reachability) == 1,
            "standalone_token_issue_query": False}


def write_bytes(path, content):
    with path.open("xb") as stream:
        stream.write(content)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--proverif", default="proverif", help="Executable path or PATH name; path is not archived")
    parser.add_argument("--timeout", type=int, default=3600)
    args = parser.parse_args()
    status = git("status", "--porcelain", "--untracked-files=all").decode()
    if status:
        raise ValueError("Formal evidence requires a clean committed working tree")
    commit = git("rev-parse", "HEAD").decode().strip()
    executable = shutil.which(args.proverif)
    if not executable:
        raise ValueError("ProVerif executable unavailable")
    tool = Path(executable)
    tool_hash = digest(tool.read_bytes())
    version = subprocess.run([str(tool), "-help"], capture_output=True, timeout=30)
    if version.returncode != 0:
        raise ValueError("ProVerif version command failed")
    input_record = default_input()
    result = build(input_record["context"], input_record["observation"])
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    dest = ROOT / "proofs/evidence" / ("authz-bridge-turepass-" + stamp)
    # Snapshot all tracked files to check protected history as well as live inputs.
    tracked = [p for p in git("ls-files", "-z").decode().split("\0") if p]
    before = {p: digest((ROOT / p).read_bytes()) for p in tracked}
    dest.mkdir(exist_ok=False)
    write_bytes(dest / ".gitattributes", b"# Preserve executed and archived bytes across checkouts.\n* -text\n")
    write_json(dest / "input.json", input_record)
    write_json(dest / "bridge-result.json", result)
    result_bytes = (dest / "bridge-result.json").read_bytes()
    model_name = "agent_communication_authz_chat_bridge.pv"
    model = derive_model(result_bytes)
    _, _, scenario_block = reconstruct(result_bytes)
    write_bytes(dest / model_name, model)
    write_bytes(dest / "proverif-version.txt", version.stdout + version.stderr)
    command = [tool.name, dest.relative_to(ROOT).as_posix() + "/" + model_name]
    manifest = {"executed_utc": stamp, "git_commit": commit, "git_status": "clean",
                "git_status_scope": "pre-run, before creating this evidence directory",
                "bridge_version": VERSION, "python_version": sys.version,
                "historical_source": result["impl_observed"]["historical_source"],
                "current_source_state": current_source_state(input_record["context"]["source_sha256"]),
                "observation": input_record["observation"], "policy_hash": result["context"]["policy_hash"],
                "evaluation_fingerprint": result["evaluation_fingerprint"],
                "bridge_result_sha256": digest(result_bytes), "source_model": MODEL,
                "source_model_sha256": TEMPLATE_SHA256, "generated_model": command[1],
                "template_path": MODEL, "template_sha256": TEMPLATE_SHA256,
                "generated_scenario_block_sha256": digest(scenario_block),
                "generated_model_sha256": digest(model),
                "proverif_executable": tool.name, "proverif_executable_sha256": tool_hash,
                "executable_resolution": "External executable supplied via --proverif; basename and bytes hash identify tool",
                "proverif_command": command, "working_directory": ".",
                "timeout_seconds": args.timeout,
                "proverif_version": (version.stdout + version.stderr).decode(errors="replace").splitlines()[0],
                "input_hashes": {p: h for p, h in before.items()
                                 if p.startswith("proofs/decision_bridge/") and p.endswith(".py")},
                "state": "running"}
    write_json(dest / "run-start.json", manifest)
    print(dest.relative_to(ROOT).as_posix(), flush=True)
    started = time.monotonic()
    exit_code = None
    timed_out = False
    with (dest / "proverif-stdout.txt").open("xb") as stdout, (dest / "proverif-stderr.txt").open("xb") as stderr:
        try:
            completed = subprocess.run([str(tool), command[1]], cwd=ROOT, stdout=stdout, stderr=stderr, timeout=args.timeout)
            exit_code = completed.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
    summary = summarize((dest / "proverif-stdout.txt").read_text(encoding="utf-8", errors="replace"))
    test_command = [sys.executable, "-B", "-m", "unittest", "discover", "-s", "proofs/decision_bridge", "-p", "test_bridge.py", "-v"]
    tests = subprocess.run(test_command, cwd=ROOT, capture_output=True, timeout=120)
    write_bytes(dest / "tests-stdout.txt", tests.stdout)
    write_bytes(dest / "tests-stderr.txt", tests.stderr)
    unchanged = all((ROOT / p).is_file() and digest((ROOT / p).read_bytes()) == h for p, h in before.items())
    passed = (exit_code == 0 and tests.returncode == 0 and unchanged and git("rev-parse", "HEAD").decode().strip() == commit
              and digest(tool.read_bytes()) == tool_hash and summary["expected_query_set"]
              and summary["chat_accept_reachable"] and summary["chat_accept_implies_token_issue"])
    manifest.update({"state": "completed" if passed else "failed", "exit_code": exit_code,
                     "timed_out": timed_out, "duration_seconds": time.monotonic() - started,
                     "result_summary": summary, "tests_exit_code": tests.returncode,
                     "tracked_files_unchanged": unchanged,
                     "git_commit_after": git("rev-parse", "HEAD").decode().strip(),
                     "post_run_git_status": git("status", "--short").decode()})
    text = "\n".join(summary["raw_results"]) + "\n"
    text += "No standalone TokenIssue reachability query. No Python refinement or service execution claim.\n"
    write_bytes(dest / "verification-summary.txt", text.encode())
    manifest["artifacts"] = {p.name: {"sha256": digest(p.read_bytes()), "bytes": p.stat().st_size} for p in dest.iterdir()}
    write_json(dest / "manifest.json", manifest)
    print(json.dumps({"state": manifest["state"], **summary}, indent=2), flush=True)
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
