"""Reproduce the stage-1 authorization diagnostic without changing baseline models."""

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
BASELINE = PROOFS / "proverif/agent_communication.pv"
EXTENDED = PROOFS / "proverif/agent_communication_authz.pv"


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def git(*args):
    return subprocess.check_output(
        ["git", *args], cwd=ROOT, encoding="utf-8"
    ).strip()


def expected_extension():
    data = BASELINE.read_bytes()
    newline = b"\r\n" if b"\r\n" in data else b"\n"
    additions = [
        ("event EndAgentAuthB(bitstring, bitstring, key).", """
(* Stage 1: proof-coverage diagnostic; policy is not an execution guard.
   All new event tuples use (issuer, recipient[, token]).
   PeerA issues the token; PeerB receives and verifies it.
   PolicyAllow(issuer, recipient) means recipient may contact issuer.
   Accept records token receipt, NOT application-message acceptance.
   No PolicyAllow event is emitted and no matcher is modeled here. *)
event PolicyAllow(bitstring, bitstring).
event PolicyDeny(bitstring, bitstring).
event TokenIssue(bitstring, bitstring, bitstring).
event Accept(bitstring, bitstring, bitstring).
"""),
        ("  event EndAgentAuthA(token, ED_A, DH_A);", """
  event TokenIssue(aid_A, aid_B, token);
"""),
        ("  event EndAgentAuthB(token, ED_A, DH_B);", """
  event Accept(aid_A, aid_B, token);
"""),
        ("query attacker(token). ", """
(* Authorization soundness at token receipt, using issuer-first tuples. *)
query issuer: bitstring, recipient: bitstring, tok: bitstring;
    event(Accept(issuer, recipient, tok))
    ==> event(PolicyAllow(issuer, recipient)).
"""),
        ("  event start();", """
  (* Fixed diagnostic scenario: PeerB is denied contact with PeerA.
     This declaration deliberately does not block the original protocol. *)
  event PolicyDeny(aid_A, aid_B);
"""),
    ]
    for anchor, body in additions:
        anchor = anchor.encode() + newline
        if data.count(anchor) != 1:
            raise ValueError(f"Baseline anchor changed or is ambiguous: {anchor!r}")
        block = (
            newline + b"(* AUTHZ-BEGIN *)" + newline
            + body.strip("\n").encode().replace(b"\n", newline) + newline
            + b"(* AUTHZ-END *)" + newline
        )
        data = data.replace(anchor, anchor + block)
    restored = re.sub(
        rb"\r?\n\(\* AUTHZ-BEGIN \*\)\r?\n.*?\(\* AUTHZ-END \*\)\r?\n",
        b"", data, flags=re.S,
    )
    if restored != BASELINE.read_bytes():
        raise ValueError("Extension modified the baseline outside additive blocks")
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proverif", default="proverif")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--build-only", action="store_true")
    args = parser.parse_args()

    expected = expected_extension()
    if EXTENDED.exists():
        if EXTENDED.read_bytes() != expected:
            raise ValueError("Existing extension differs; refusing to overwrite it")
    else:
        EXTENDED.write_bytes(expected)
    print("Verified: removing AUTHZ blocks restores the baseline byte for byte.", flush=True)
    if args.build_only:
        return

    executable = shutil.which(args.proverif)
    if not executable:
        raise FileNotFoundError(f"ProVerif executable not found: {args.proverif}")
    executable = str(Path(executable).resolve())
    output = args.output or (
        PROOFS / "evidence" / ("authz-stage1-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    )
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    models = [PROOFS / "proverif/registration.pv", BASELINE, EXTENDED]
    manifest = {
        "started_utc": utc_now(),
        "base_commit": git("rev-parse", "HEAD"),
        "branch": git("branch", "--show-current"),
        "pre_run_git_status": git("status", "--porcelain=v1", "--untracked-files=all"),
        "proverif_executable": executable,
        "proverif_sha256": sha256(Path(executable)),
        "runner_sha256": sha256(Path(__file__).resolve()),
        "model_sha256_before": {str(p.relative_to(ROOT)): sha256(p) for p in models},
        "extension_is_additive_only": True,
        "runs": [],
        "completed": False,
    }
    manifest_path = output / "manifest.json"

    def save_manifest():
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    save_manifest()
    version = subprocess.run([executable, "-help"], capture_output=True, check=False)
    (output / "proverif-version.txt").write_bytes(version.stdout + version.stderr)
    manifest["proverif_version"] = (version.stdout + version.stderr).decode(errors="replace").splitlines()[0]
    print(f"Evidence directory: {output}", flush=True)
    try:
        for model in models:
            stdout = output / f"{model.stem}.stdout.txt"
            stderr = output / f"{model.stem}.stderr.txt"
            command = [executable, str(model)]
            run = {"model": str(model.relative_to(ROOT)), "command": command,
                   "started_utc": utc_now(), "stdout": stdout.name, "stderr": stderr.name}
            manifest["runs"].append(run)
            save_manifest()
            print(f"Running {model.name} ...", flush=True)
            started = time.monotonic()
            with stdout.open("wb") as out, stderr.open("wb") as err:
                result = subprocess.run(command, cwd=PROOFS, stdout=out, stderr=err, check=False)
            log = stdout.read_text(encoding="utf-8", errors="replace")
            results = re.findall(r"^RESULT .+$", log, flags=re.M)
            run.update({"exit_code": result.returncode, "elapsed_seconds": round(time.monotonic() - started, 3),
                        "finished_utc": utc_now(), "results": results,
                        "stdout_sha256": sha256(stdout), "stderr_sha256": sha256(stderr)})
            save_manifest()
            print("\n".join(results), flush=True)
            if result.returncode != 0 or not results:
                raise RuntimeError(f"{model.name} failed; inspect {stdout} and {stderr}")

        registration, baseline, extended = [r["results"] for r in manifest["runs"]]
        authz = [line for line in extended if line.startswith("RESULT event(Accept(")]
        manifest["checks"] = {
            "registration_four_results": len(registration) == 4,
            "baseline_eleven_results": len(baseline) == 11,
            "extended_twelve_results": len(extended) == 12,
            "baseline_seven_reachable_events": sum(line.startswith("RESULT not event(") and line.endswith("is false.") for line in baseline) == 7,
            "baseline_three_authentication_correspondences_true": sum(" ==> " in line and line.endswith("is true.") for line in baseline) == 3,
            "baseline_token_secrecy_true": any(line.startswith("RESULT not attacker") and line.endswith("is true.") for line in baseline),
            "all_baseline_results_preserved": [line for line in extended if line not in authz] == baseline,
            "authorization_correspondence_false": len(authz) == 1 and authz[0].endswith("is false."),
        }
        manifest["model_sha256_after"] = {str(p.relative_to(ROOT)): sha256(p) for p in models}
        manifest["checks"]["models_unchanged_during_run"] = manifest["model_sha256_before"] == manifest["model_sha256_after"]
        manifest["checks"]["runner_unchanged_during_run"] = manifest["runner_sha256"] == sha256(Path(__file__).resolve())
        manifest["checks"]["git_head_unchanged_during_run"] = manifest["base_commit"] == git("rev-parse", "HEAD")
        summary = "\n\n".join(r["model"] + "\n" + "\n".join(r["results"]) for r in manifest["runs"])
        (output / "verification-summary.txt").write_text(summary + "\n", encoding="utf-8")

        full_log = (output / "agent_communication_authz.stdout.txt").read_text(encoding="utf-8", errors="replace")
        lines = full_log.splitlines(keepends=True)
        starts = [i for i, line in enumerate(lines) if "Starting query " in line and "event(Accept(" in line]
        if len(starts) != 1:
            raise RuntimeError("Cannot uniquely locate authorization query trace in raw output")
        start = starts[0]
        end = next(i + 1 for i in range(start, len(lines)) if lines[i].startswith("RESULT event(Accept("))
        excerpt = "".join(lines[start:end])
        (output / "authorization-trace.txt").write_text(excerpt, encoding="utf-8")
        manifest["authorization_trace_source"] = {"file": "agent_communication_authz.stdout.txt", "first_line": start + 1, "last_line": end}
        manifest["checks"]["authorization_trace_reconstructed"] = "A trace has been found." in excerpt
        manifest["checks"]["deny_event_in_authorization_trace"] = "event PolicyDeny(" in excerpt
        manifest["completed"] = all(manifest["checks"].values())
        if not manifest["completed"]:
            raise RuntimeError("Evidence checks failed: " + str(manifest["checks"]))
        print("All evidence checks passed.", flush=True)
    finally:
        manifest["finished_utc"] = utc_now()
        manifest["post_run_git_status"] = git("status", "--porcelain=v1", "--untracked-files=all")
        manifest["evidence_sha256"] = {p.name: sha256(p) for p in output.iterdir() if p.is_file() and p != manifest_path}
        save_manifest()
        print(f"Manifest: {manifest_path}", flush=True)


if __name__ == "__main__":
    main()
