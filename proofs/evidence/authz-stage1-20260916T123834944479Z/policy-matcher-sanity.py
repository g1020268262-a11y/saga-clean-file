"""Read-only check of the current Python matcher; not an end-to-end attack."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from saga.common.contact_policy import aid_specificity, check_rulebook, match

rules = [
    {"pattern": "alice@example.com:*", "budget": -1},
    {"pattern": "*", "budget": 10},
]
aid = "alice@example.com:agent"
result = {
    "executed_utc": datetime.now(timezone.utc).isoformat(),
    "base_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
    "source": "saga/common/contact_policy.py",
    "source_sha256": hashlib.sha256((ROOT / "saga/common/contact_policy.py").read_bytes()).hexdigest(),
    "python_version": sys.version,
    "aid": aid,
    "rules": rules,
    "rulebook_valid": check_rulebook(rules),
    "specificities": [aid_specificity(rule["pattern"]) for rule in rules],
    "expected_under_documented_most_specific_semantics": -1,
    "actual_specific_deny_then_wildcard_allow": match(rules, aid),
    "actual_wildcard_allow_then_specific_deny": match(list(reversed(rules)), aid),
    "scope": "Direct call of the unmodified matcher only; no Provider, network, token issuance, or message acceptance tested.",
}
if not (result["rulebook_valid"] and result["specificities"] == [70, 0]
        and result["actual_specific_deny_then_wildcard_allow"] == 10
        and result["actual_wildcard_allow_then_specific_deny"] == -1):
    raise RuntimeError("Matcher behavior differs from this recorded witness")
Path(__file__).with_suffix(".json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
print(json.dumps(result, indent=2))
