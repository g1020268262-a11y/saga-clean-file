import fnmatch

# 模拟原项目中的 specificity 计算逻辑
# 规范要求：匹配越精确的规则，优先级越高
def aid_specificity(pattern):
    if pattern is None:
        return -1
    if pattern == "*":
        return 0
    # 简单计算非通配符的长度作为精确度权重
    return len(pattern.replace("*", ""))

# 1. 真实项目中存在缺陷的 matcher 逻辑
def buggy_match(contact_rulebook, t_aid):
    best_pattern = None
    budget = 0

    for rule in contact_rulebook:
        if fnmatch.fnmatch(t_aid, rule['pattern']):
            if aid_specificity(rule['pattern']) > aid_specificity(best_pattern):
                budget = rule['budget']
                # [致命缺陷]: 此处原代码遗漏了 best_pattern 的更新
                # best_pattern = rule['pattern'] 
    return budget

# 2. 修复后符合原论文规范的 matcher 逻辑
def fixed_match(contact_rulebook, t_aid):
    best_pattern = None
    budget = 0

    for rule in contact_rulebook:
        if fnmatch.fnmatch(t_aid, rule['pattern']):
            if aid_specificity(rule['pattern']) > aid_specificity(best_pattern):
                budget = rule['budget']
                # [修复]: 及时更新当前的最高优先级 pattern
                best_pattern = rule['pattern'] 
    return budget

if __name__ == "__main__":
    # 构造受害者策略：试图阻止 Mallory (-1)，但允许其他所有人 (10)
    contact_rulebook = [
        {"pattern": "mallory@example.com:*", "budget": -1},  # Specific Deny
        {"pattern": "*",                     "budget": 10}   # Wildcard Allow
    ]

    # 攻击者发起连接时的实际身份标识
    attacker_aid = "mallory@example.com:evil_agent"

    print("=== SAGA Matcher Bug Proof of Concept ===")
    print(f"Attacker AID   : {attacker_aid}")
    print(f"Policy Rulebook: {contact_rulebook}\n")

    # 预期结果（规范语义）
    expected_budget = fixed_match(contact_rulebook, attacker_aid)
    print(f"[Specification] Expected Budget: {expected_budget} ", end="")
    print("(DENY - Most specific rule won)" if expected_budget <= 0 else "(ALLOW)")

    # 实际运行结果（实现缺陷）
    actual_budget = buggy_match(contact_rulebook, attacker_aid)
    print(f"[Implementation] Actual Budget : {actual_budget} ", end="")
    print("(ALLOW - Wildcard incorrectly overrode specific deny!)" if actual_budget > 0 else "(DENY)")

    print("\n--------------------------------------------------")
    if actual_budget > 0 and expected_budget <= 0:
        print("[!] VULNERABILITY CONFIRMED: Order-dependent authorization bypass succeeded.")
    else:
        print("[ ] No bypass detected.")