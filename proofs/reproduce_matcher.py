"""Read-only reproduction of the recorded production matcher inconsistency."""

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from saga.common.contact_policy import aid_specificity, check_rulebook, match


RULES = [
    {"pattern": "alice@example.com:*", "budget": -1},
    {"pattern": "*", "budget": 10},
]
TARGET = "alice@example.com:agent"


def main() -> None:
    result = {
        "target": TARGET,
        "rules": RULES,
        "rulebook_valid": check_rulebook(RULES),
        "specificities": [aid_specificity(rule["pattern"]) for rule in RULES],
        "intended_most_specific_budget": -1,
        "production_budget_in_recorded_order": match(RULES, TARGET),
        "production_budget_in_reverse_order": match(list(reversed(RULES)), TARGET),
    }
    print(json.dumps(result, indent=2))
    if not (
        result["rulebook_valid"]
        and result["specificities"] == [70, 0]
        and result["production_budget_in_recorded_order"] == 10
        and result["production_budget_in_reverse_order"] == -1
    ):
        raise SystemExit("Matcher behavior differs from the recorded witness")


if __name__ == "__main__":
    main()
