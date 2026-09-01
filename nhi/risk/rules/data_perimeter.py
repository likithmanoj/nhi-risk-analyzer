from nhi.risk.helpers import (
    match_action,
    analyze_resources,
)

def analyze_policy_for_kms_decryption(policies, identityType, identityName): # IAM_16
    findings = []
    for policy in policies:
        statements = policy['PolicyDocument']['Statement']
        if isinstance(statements, dict):
            statements = [statements]
        for statement in statements:
            if "Action" not in statement or "Resource" not in statement or "Effect" not in statement:
                continue
            target_actions = ["kms:Decrypt", "kms:ReEncrypt*", "kms:*"]
            for target_action in target_actions:
                if (str(statement.get('Effect')) == "Allow") and analyze_resources(statement.get('Resource')) and match_action(statement.get('Action'), target_action):
                    findings.append({
                        "RuleID": "IAM_16",
                        "Severity": "HIGH",
                        "Title": f"Unrestricted KMS Decryption via {target_action}",
                        "IdentityType": identityType,
                        "IdentityName": identityName,
                        "PolicyName": policy.get("PolicyName", "Unknown"),
                        "PolicyArn": policy.get("PolicyArn"),
                        "Action": statement.get("Action"),
                        "Resource": statement.get("Resource")
                    })
                    break
    return findings

def analyze_policy_for_s3_exfiltration(policies, identityType, identityName): # IAM_14
    findings = []
    for policy in policies:
        statements = policy['PolicyDocument']['Statement']
        if isinstance(statements, dict):
            statements = [statements]
        for statement in statements:
            if "Action" not in statement or "Resource" not in statement or "Effect" not in statement:
                continue
            target_actions = ["s3:GetObject", "s3:GetObjectVersion", "s3:*"]
            for target_action in target_actions:
                if (str(statement.get('Effect')) == "Allow") and analyze_resources(statement.get('Resource')) and match_action(statement.get('Action'), target_action):
                    findings.append({
                        "RuleID": "IAM_14",
                        "Severity": "HIGH",
                        "Title": f"Unrestricted S3 Data Exfiltration via {target_action}",
                        "IdentityType": identityType,
                        "IdentityName": identityName,
                        "PolicyName": policy.get("PolicyName", "Unknown"),
                        "PolicyArn": policy.get("PolicyArn"),
                        "Action": statement.get("Action"),
                        "Resource": statement.get("Resource")
                    })
                    break
    return findings
