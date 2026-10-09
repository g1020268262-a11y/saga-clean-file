"""Verify independent Provider/receiver authorization control scenarios."""

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
SCENARIOS = {
    "p_allow_r_allow": (True, True, True),
    "p_deny_r_allow": (False, False, False),
    "p_allow_r_deny": (True, False, False),
}
MODELS = {
    name: PROOFS / "proverif" / f"agent_communication_authz_chat_{name}.pv"
    for name in SCENARIOS
}
SOURCES = (
    PROOFS / "build_authz_chat_gates.py",
    PROOFS / "run_authz_chat_gates.py",
    PROOFS / "proverif/agent_communication_authz_chat_allow.pv",
    PROOFS / "proverif/registration.pv",
    PROOFS / "proverif/agent_communication.pv",
    PROOFS / "proverif/agent_communication_authz.pv",
    ROOT / "saga/common/contact_policy.py",
    ROOT / "saga/provider/provider.py",
    ROOT / "saga/agent.py",
    *MODELS.values(),
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, encoding="utf-8").strip()


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def source_hashes() -> dict[str, str]:
    return {path.relative_to(ROOT).as_posix(): digest(path) for path in SOURCES}


def result(results: list[str], marker: str) -> bool:
    matches = [line for line in results if line.startswith("RESULT " + marker)]
    if len(matches) != 1:
        raise RuntimeError(f"Expected one {marker!r} result; found {len(matches)}")
    return matches[0].endswith("is false.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proverif", default="proverif")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    executable_name = shutil.which(args.proverif)
    if executable_name is None:
        raise FileNotFoundError(args.proverif)
    executable = Path(executable_name).resolve()
    status = git("status", "--porcelain=v1", "--untracked-files=all")
    if status:
        raise RuntimeError("Commit model and runner changes before collecting evidence")

    output = (args.output or PROOFS / "evidence" /
              ("authz-chat-gates-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))).resolve()
    output.mkdir(parents=True, exist_ok=False)
    before = source_hashes()
    manifest = {
        "started_utc": now(),
        "git_head_before": git("rev-parse", "HEAD"),
        "branch": git("branch", "--show-current"),
        "pre_run_git_status": status,
        "proverif_executable_name": executable.name,
        "proverif_sha256": digest(executable),
        "source_sha256_before": before,
        "scope": "Independent abstract control gates; no rulebook matcher or TLS proof",
        "models": [],
        "completed": False,
    }
    manifest_path = output / "manifest.json"

    def save() -> None:
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    save()
    version = subprocess.run([str(executable), "-help"], capture_output=True, check=False)
    (output / "proverif-version.txt").write_bytes(version.stdout + version.stderr)
    print(f"Evidence directory: {output}", flush=True)

    try:
        for scenario, model in MODELS.items():
            stdout = output / f"{scenario}.stdout.txt"
            stderr = output / f"{scenario}.stderr.txt"
            run = {
                "scenario": scenario,
                "model": model.relative_to(ROOT).as_posix(),
                "working_directory": "proofs/proverif",
                "command": ["<proverif>", model.name],
                "started_utc": now(),
                "stdout": stdout.name,
                "stderr": stderr.name,
            }
            manifest["models"].append(run)
            save()
            print(f"Running {scenario} ...", flush=True)
            started = time.monotonic()
            with stdout.open("wb") as out, stderr.open("wb") as err:
                process = subprocess.run(
                    [str(executable), model.name], cwd=model.parent,
                    stdout=out, stderr=err, check=False,
                )
            log = stdout.read_text(encoding="utf-8", errors="replace")
            run.update({
                "exit_code": process.returncode,
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "finished_utc": now(),
                "results": re.findall(r"^RESULT .+$", log, flags=re.M),
                "stdout_sha256": digest(stdout),
                "stderr_sha256": digest(stderr),
            })
            save()
            print("\n".join(run["results"]), flush=True)
            if process.returncode != 0 or len(run["results"]) != 5:
                raise RuntimeError(f"ProVerif failed for {scenario}")

        checks = {}
        for run in manifest["models"]:
            expected = SCENARIOS[run["scenario"]]
            actual = tuple(result(run["results"], "not event(" + event)
                           for event in ("ProviderRelease(", "TokenIssue(", "ChatAccept("))
            # A false reachability query means the event is reachable.
            checks[run["scenario"] + "_reachability"] = actual == expected
            run["reachable"] = dict(zip(
                ("provider_release", "token_issue", "chat_accept"), actual
            ))

        allowed = manifest["models"][0]["results"]
        for event in ("TokenIssue(", "ChatSend("):
            matches = [line for line in allowed if line.startswith("RESULT event(ChatAccept(")
                       and "==> event(" + event in line]
            checks["allowed_chat_implies_" + event[:-1]] = (
                len(matches) == 1 and matches[0].endswith("is true.")
            )
        checks["sources_unchanged"] = before == source_hashes()
        checks["git_head_unchanged"] = manifest["git_head_before"] == git("rev-parse", "HEAD")
        manifest["checks"] = checks
        (output / "verification-summary.txt").write_text(
            "\n\n".join(
                run["scenario"] + "\n" + "\n".join(run["results"])
                for run in manifest["models"]
            ) + "\n", encoding="utf-8"
        )
        manifest["completed"] = all(checks.values())
        if not manifest["completed"]:
            raise RuntimeError(f"Evidence checks failed: {checks}")
    finally:
        manifest["finished_utc"] = now()
        manifest["git_head_after"] = git("rev-parse", "HEAD")
        manifest["post_run_git_status"] = git("status", "--porcelain=v1", "--untracked-files=all")
        manifest["source_sha256_after"] = source_hashes()
        manifest["evidence_sha256"] = {
            path.name: digest(path) for path in output.iterdir()
            if path.is_file() and path != manifest_path
        }
        save()
        print(f"Manifest: {manifest_path}", flush=True)


if __name__ == "__main__":
    main()
