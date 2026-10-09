"""Explicit NEW function-level observations, separate from historical evidence and spec."""
from datetime import datetime, timezone
import sys
from bridge import ROOT, SOURCE, digest, git, write_json


def main():
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(ROOT))
    from saga.common.contact_policy import match
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    dest = ROOT / "proofs/decision_bridge/observations" / stamp
    dest.mkdir(parents=True, exist_ok=False)
    source_hash = digest((ROOT / SOURCE).read_bytes())
    for name, budget in (("allow", 10), ("deny", -1)):
        rules = [{"pattern": "*", "budget": budget}]
        actual = match(rules, "alice@example.com:agent")
        write_json(dest / (name + ".json"), {"executed_utc": stamp,
            "base_commit": git("rev-parse", "HEAD").decode().strip(),
            "source": SOURCE, "source_sha256": source_hash,
            "collector_sha256": digest(__import__('pathlib').Path(__file__).read_bytes()),
            "python_version": sys.version, "aid": "alice@example.com:agent",
            "rules": rules, "actual_budget": actual,
            "scope": "NEW direct production matcher call only; no service or ProVerif execution"})
    if digest((ROOT / SOURCE).read_bytes()) != source_hash:
        raise RuntimeError("Source changed during collection")
    print(dest.relative_to(ROOT).as_posix())


if __name__ == "__main__":
    main()
