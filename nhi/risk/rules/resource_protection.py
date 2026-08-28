from nhi.risk.helpers import (
    match_action,
    analyze_resources,
)

def analyze_policy_for_defense_evasion(policies, identityType, identityName): # IAM_15
    findings = []
    for policy in policies:
        statements = policy['PolicyDocument']['Statement']
        if isinstance(statements, dict):
            statements = [statements]
        for statement in statements:
            if "Action" not in statement or "Resource" not in statement or "Effect" not in statement:
                continue
            target_actions = [
                "cloudtrail:StopLogging",
                "cloudtrail:DeleteTrail",
                "guardduty:DeleteDetector",
                "guardduty:DisassociateFromMasterAccount",
                "kms:DisableKey",
                "kms:ScheduleKeyDeletion"
            ]
            for target_action in target_actions:
                if (str(statement.get('Effect')) == "Allow") and analyze_resources(statement.get('Resource')) and match_action(statement.get('Action'), str(target_action)):
                    findings.append({
                        "RuleID": "IAM_15",
                        "Severity": "CRITICAL",
                        "Title": f"Security Audit Defense Evasion via {target_action}",
                        "IdentityType": identityType,
                        "IdentityName": identityName,
                        "PolicyName": policy.get("PolicyName", "Unknown"),
                        "Action": statement.get("Action"),
                        "Resource": statement.get("Resource")
                    })
    return findings