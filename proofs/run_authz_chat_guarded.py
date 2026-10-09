"""Run guarded allow/deny chat models and retain their verification evidence."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import time


ROOT = Path(__file__).resolve().parent.parent
PROOFS = ROOT / "proofs"
MODELS = (
    PROOFS / "proverif/agent_communication_authz_chat_allow.pv",
    PROOFS / "proverif/agent_communication_authz_chat_deny.pv",
)
PROTECTED = (
    PROOFS / "proverif/registration.pv",
    PROOFS / "proverif/agent_communication.pv",
    PROOFS / "proverif/agent_communication_authz.pv",
    ROOT / "saga/common/contact_policy.py",
    ROOT / "saga/provider/provider.py",
    ROOT / "saga/agent.py",
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def git(*args):
    return subprocess.check_output(
        ["git", *args], cwd=ROOT, encoding="utf-8"
    ).strip()


def result_for(results, predicate):
    matches = [line for line in results if predicate(line)]
    if len(matches) != 1:
        raise RuntimeError(f"Expected one matching result, found {len(matches)}")
    return matches[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proverif", default="proverif")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    executable = shutil.which(args.proverif)
    if executable is None:
        raise FileNotFoundError(args.proverif)
    executable = Path(executable).resolve()
    output = (args.output or PROOFS / "evidence" /
              ("authz-chat-guarded-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))).resolve()
    output.mkdir(parents=True, exist_ok=False)

    sources = (*PROTECTED, *MODELS, Path(__file__).resolve())
    before = {str(path.relative_to(ROOT)): digest(path) for path in sources}
    manifest = {
        "started_utc": utc_now(),
        "git_head_before": git("rev-parse", "HEAD"),
        "branch": git("branch", "--show-current"),
        "pre_run_git_status": git("status", "--porcelain=v1", "--untracked-files=all"),
        "proverif_executable": str(executable),
        "proverif_sha256": digest(executable),
        "source_sha256_before": before,
        "models": [],
        "scope": "Guarded allow/deny controls only; no implementation-mismatch execution model.",
        "completed": False,
    }
    manifest_path = output / "manifest.json"

    def save():
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    save()
    version = subprocess.run([str(executable), "-help"], capture_output=True, check=False)
    (output / "proverif-version.txt").write_bytes(version.stdout + version.stderr)
    print(f"Evidence directory: {output}", flush=True)

    try:
        for model in MODELS:
            stdout = output / f"{model.stem}.stdout.txt"
            stderr = output / f"{model.stem}.stderr.txt"
            command = [str(executable), str(model)]
            run = {"model": str(model.relative_to(ROOT)), "command": command,
                   "started_utc": utc_now(), "stdout": stdout.name, "stderr": stderr.name}
            manifest["models"].append(run)
            save()
            print(f"Running {model.name} ...", flush=True)
            started = time.monotonic()
            with stdout.open("wb") as out, stderr.open("wb") as err:
                process = subprocess.run(command, cwd=PROOFS, stdout=out, stderr=err, check=False)
            log = stdout.read_text(encoding="utf-8", errors="replace")
            run.update({"exit_code": process.returncode,
                        "elapsed_seconds": round(time.monotonic() - started, 3),
                        "finished_utc": utc_now(),
                        "results": re.findall(r"^RESULT .+$", log, flags=re.M),
                        "stdout_sha256": digest(stdout), "stderr_sha256": digest(stderr)})
            save()
            print("\n".join(run["results"]), flush=True)
            if process.returncode != 0 or not run["results"]:
                raise RuntimeError(f"ProVerif failed for {model.name}")

        allow, deny = [run["results"] for run in manifest["models"]]
        reachable = lambda line: line.startswith("RESULT not event(ChatAccept(")
        authz = lambda line: line.startswith("RESULT event(ChatAccept(") and "PolicyAllow(" in line
        issue = lambda line: line.startswith("RESULT event(ChatAccept(") and "TokenIssue(" in line
        matcher = lambda line: line.startswith("RESULT event(ChatAccept(") and "MatcherAllow(" in line
        send = lambda line: line.startswith("RESULT event(ChatAccept(") and "ChatSend(" in line
        manifest["checks"] = {
            "allow_chat_reachable": result_for(allow, reachable).endswith("is false."),
            "allow_policy_correspondence": result_for(allow, authz).endswith("is true."),
            "allow_issued_token_correspondence": result_for(allow, issue).endswith("is true."),
            "allow_matcher_correspondence": result_for(allow, matcher).endswith("is true."),
            "allow_chat_send_correspondence": result_for(allow, send).endswith("is true."),
            "deny_chat_unreachable": result_for(deny, reachable).endswith("is true."),
            "sources_unchanged": before == {
                str(path.relative_to(ROOT)): digest(path) for path in sources
            },
            "git_head_unchanged": manifest["git_head_before"] == git("rev-parse", "HEAD"),
        }
        (output / "verification-summary.txt").write_text(
            "\n\n".join(run["model"] + "\n" + "\n".join(run["results"])
                        for run in manifest["models"]) + "\n", encoding="utf-8"
        )
        manifest["completed"] = all(manifest["checks"].values())
        if not manifest["completed"]:
            raise RuntimeError(f"Evidence checks failed: {manifest['checks']}")
    finally:
        manifest["finished_utc"] = utc_now()
        manifest["git_head_after"] = git("rev-parse", "HEAD")
        manifest["post_run_git_status"] = git("status", "--porcelain=v1", "--untracked-files=all")
        manifest["source_sha256_after"] = {
            str(path.relative_to(ROOT)): digest(path) for path in sources
        }
        manifest["evidence_sha256"] = {
            path.name: digest(path) for path in output.iterdir()
            if path.is_file() and path != manifest_path
        }
        save()
        print(f"Manifest: {manifest_path}", flush=True)


if __name__ == "__main__":
    main()
