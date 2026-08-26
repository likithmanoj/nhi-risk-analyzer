def check_permissive_principal(principal):
    if principal == "*":
        return True
    
    if isinstance(principal, dict):
        aws_entry = principal.get("AWS")
        if aws_entry == "*":
            return True
        if isinstance(aws_entry, list) and "*" in aws_entry:
            return True
            
    return False


def check_assume_role_action(action):
    if isinstance(action, str):
        actions = [action]
    elif isinstance(action, list):
        actions = action
    else:
        return False

    for act in actions:
        if act in ["*", "sts:*", "sts:AssumeRole"]:
            return True

    return False


def analyze_trust_policy(trust_policy: dict, role_name: str) -> list: #IAM_10
    findings = []
    if not trust_policy or not isinstance(trust_policy, dict):
        return findings

    statements = trust_policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if not isinstance(statement, dict):
            continue

        if statement.get("Effect") != "Allow":
            continue

        action = statement.get("Action")
        principal = statement.get("Principal")

        if not action or not principal:
            continue

        if check_assume_role_action(action) and check_permissive_principal(principal):
            findings.append({
                "RuleID": "IAM_10",
                "Severity": "CRITICAL",
                "IdentityType": "Role",
                "IdentityName": role_name,
                "Title": "Overly Permissive Trust Policy Allowing Public AssumeRole",
                "Finding": "Trust policy allows unrestricted assume role access (*)",
                "Principal": principal,
                "Action": action,
            })

    return findings