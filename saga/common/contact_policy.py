"""
    Common contact policy package for SAGA
"""
import fnmatch
from saga.common.logger import Logger as logger


def check_aid(aid):
    """
    Checks if the AID is in the right format.
    """
    # AID is in the form of:
    # alice@her_email.com:bobafet
    components = aid.split(":", 1)
    if len(components) != 2:
        return False
    uid, name = components[0], components[1]
    if not isinstance(uid, str) or not isinstance(name, str):
        return False
    # Check if the uid and name are valid:
    # The uid must only have 1 '@' character and NO ':' characters.
    if uid.count('@') != 1 or uid.count(':') != 0:
        return False
    # Check the name format:
    # The name must not have any ':' characters.
    if name.count(':') != 0:
        return False
    return True


def check_rulebook(rulebook):
    """
    Checks if the contact rulebook is valid.
    The rulebook is a list of rules, where each rule is a dictionary with the following keys:
    """
    
    if rulebook is None:
        return False

    for rule in rulebook:
        # Rules are in the form of:
        # {
        #   "pattern": "alice@her_email.com:bobafet",
        #   "budget": 10,
        # }
        pattern_component = rule.get("pattern", None)
        if pattern_component is None:
            logger.error(f"Invalid rulebook format: {rule}. No pattern found.")
            return False
        budget_component = rule.get("budget", None)
        if budget_component is None:
            logger.error(f"Invalid rulebook format: {rule}. No budget found.")
            return False
        # Check if the pattern is in the right format.
        if not isinstance(pattern_component, str):
            logger.error(f"Invalid rulebook format: {pattern_component}. Pattern is not a string.")
            return False
        # Check if the budget is in the right format.
        if not isinstance(budget_component, int):
            logger.error(f"Invalid rulebook format: {budget_component}. Budget is not an integer.")
            return False

        # Check if the budget is -1 or greater.
        if budget_component < -1:
            logger.error(f"Invalid rulebook format: {rule}. Budget is less than -1.")
            return False

        # Check if the pattern is a valid rule.
        pattern_component = pattern_component.split(":")
        if len(pattern_component) == 1:
            if pattern_component[0] != "*":
                logger.error(f"Invalid rulebook format: {rule}")
                return False
            continue
        
        if len(pattern_component) != 2:
            logger.error(f"Invalid rulebook format: {rule}")
            return False
        
        uid, name = pattern_component[0], pattern_component[1]
        if not isinstance(uid, str) or not isinstance(name, str):
            return False
    return True


def pattern_specificity_component(component, weight=1):
    score = 0
    i = 0
    while i < len(component):
        c = component[i]
        if c == '*':
            score += 1 * weight
        elif c == '?':
            score += 2 * weight
        elif c == '[':
            end = component.find(']', i)
            if end != -1:
                score += 3 * weight
                i = end
            else:
                score += 1 * weight
        else:
            score += 4 * weight
        i += 1
    return score


def aid_specificity(aid_pattern):
    """
    Returns the specificity score of a given AID pattern.
    The more specific the pattern, the higher the score.
    The score is calculated by the number of wildcards in the pattern.
    """
    if aid_pattern is None:
        return -1
    if aid_pattern.strip() == '*':
        return 0
    uid_part, nametag_part = aid_pattern.split(':', 1)
    # UID wildcards lead to more general rules, thus decreased weight.
    uid_score = pattern_specificity_component(uid_part, weight=1)
    # Nametag wildcards lead to more specific rules, thus increased weight.
    nametag_score = pattern_specificity_component(nametag_part, weight=2)
    return uid_score + nametag_score


def compare_aid_patterns(p1, p2):
    s1 = aid_specificity(p1)
    s2 = aid_specificity(p2)
    if s1 > s2:
        return f"'{p1}' is more specific than '{p2}'"
    elif s1 < s2:
        return f"'{p2}' is more specific than '{p1}'"
    else:
        return f"'{p1}' and '{p2}' are equally specific"


def match(contact_rulebook, t_aid):
    """
    Returns the budget for a given AID.
    The budget is calculated by the specificity of the AID pattern.
    The budget that corresponds to the most specific pattern is returned.
    """
    # Check that the t_aid is valid (correct format)
    if not check_aid(t_aid):
        return -2 # Bad aid format error.
    
    # Init the vars to be returned
    best_pattern = None
    budget = 0
    # Check for matching pattern:
    for rule in contact_rulebook:
        if fnmatch.fnmatch(t_aid, rule['pattern']):
            if aid_specificity(rule['pattern']) > aid_specificity(best_pattern):
                budget = rule['budget']
    return budget


if __name__ == "__main__":
    # Test the functions
    rulebook = [
        {"pattern": "*", "budget": 100}
    ]
    i_aid = "alice@her_email.com:bobafet"
    print(match(rulebook, i_aid))