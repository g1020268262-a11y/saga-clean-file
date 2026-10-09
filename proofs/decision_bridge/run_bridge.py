"""Replay historical observations; never execute the production matcher."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
from bridge import (ROOT, ARCHIVE, SOURCE, MODEL, VERSION, read, digest, git,
                    make_context, build, generate, write_json, current_source_state)


def default_input():
    data = read(ARCHIVE)
    return {"context": make_context(data["rules"], data["aid"], data["source_sha256"], data["base_commit"], "stage1-alice"),
            "observation": {"path": ARCHIVE, "sha256": digest((ROOT / ARCHIVE).read_bytes()),
                            "format": "stage1", "field": "actual_specific_deny_then_wildcard_allow"}}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", help="Repository-relative input JSON containing context and observation")
    parser.add_argument("--output", help="New repository-relative directory; must not already exist")
    args = parser.parse_args()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    dest = (ROOT / (args.output or f"proofs/decision_bridge/evidence/{stamp}")).resolve()
    if not dest.is_relative_to(ROOT) or dest == ROOT:
        raise ValueError("Output must be a new directory inside repository")
    if args.input:
        input_record = read(args.input)
    else:
        input_record = default_input()
    result = build(input_record["context"], input_record["observation"])
    # Validate before creating output; then independently consume the saved pair.
    if result["status"] == "OK":
        generate(result)
    dest.mkdir(parents=True, exist_ok=False)
    write_json(dest / "input.json", input_record)
    write_json(dest / "bridge-result.json", result)
    saved = json.loads((dest / "bridge-result.json").read_text(encoding="utf-8"))
    fragment = generate(saved) if saved["status"] == "OK" else None
    if fragment:
        with (dest / "scenario_turepass_from_bridge.inc").open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(fragment)
    summary = f"Status: {result['status']}\n"
    if result["status"] == "OK":
        summary += f"Spec: {result['spec']['decision']}; observation: {result['impl_observed']['decision']}; divergence: {result['divergence']}\n"
    summary += "Fragment generated: " + str(fragment is not None) + "\nNo ProVerif run. No refinement proof. Historical evidence unchanged.\n"
    with (dest / "summary.txt").open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(summary)
    paths = [MODEL, input_record["observation"]["path"]]
    paths += [p.relative_to(ROOT).as_posix() for p in Path(__file__).parent.glob("*.py")]
    write_json(dest / "manifest.json", {"executed_utc": stamp, "git_commit": git("rev-parse", "HEAD").decode().strip(),
               "git_status": git("status", "--short").decode(), "generator_version": VERSION,
               "current_source_state": current_source_state(input_record["context"]["source_sha256"]),
               "command": "python proofs/decision_bridge/run_bridge.py" + (f" --input {args.input}" if args.input else ""),
               "input_hashes": {p: digest((ROOT / p).read_bytes()) for p in paths},
               "output_hashes": {p.name: digest(p.read_bytes()) for p in dest.iterdir()},
               "proverif_executed": False})
    print(dest.relative_to(ROOT).as_posix())
    print(summary)


if __name__ == "__main__":
    main()
