from nhi.risk.helpers import (
    match_action,
    analyze_resources,
    has_passed_to_service_condition,
)
def analyze_passrole_with_wildcard(policies,identityType,identityName): #IAM_04
    findings = []
    for policy in policies:
            statements = policy["PolicyDocument"]["Statement"]
            if isinstance(policy["PolicyDocument"]["Statement"], dict):
                statements = [statements]
            for statement in statements:    
                    if "Action" not in statement or "Resource" not in statement or "Effect" not in statement:
                        continue
                    if(str(statement.get('Effect'))=="Allow") and analyze_resources(statement.get('Resource')) and match_action(statement.get('Action'), "iam:PassRole") and not has_passed_to_service_condition(statement.get("Condition")):
                        findings.append(
                              {
                            "RuleID": "IAM_04",
                            "Severity": "HIGH",
                            "Title": "Privilege Escalation via iam:PassRole granted with Wildcard Resource",
                            "IdentityType": identityType,
                            "IdentityName": identityName,
                            "PolicyName": policy.get("PolicyName", "Unknown"),
                            "PolicyArn": policy.get("PolicyArn"),
                            "Action": statement.get("Action"),
                            "Resource": statement.get("Resource"),
                                }                     
                        )                  
    return findings

def analyze_create_policy_version(policies, identityType, identityName): #IAM_05
    findings = []
    for policy in policies:
        statements = policy['PolicyDocument']['Statement']
        if isinstance(statements, dict):
            statements = [statements]
        for statement in statements:
            if "Action" not in statement or "Resource" not in statement or "Effect" not in statement:
                continue
            if(str(statement.get('Effect'))=="Allow") and analyze_resources(statement.get('Resource'))  and match_action(statement.get('Action'), "iam:CreatePolicyVersion"):
                findings.append({
                        "RuleID": "IAM_05",
                        "Severity": "CRITICAL",
                        "Title": "Privilege Escalation via iam:CreatePolicyVersion",
                        "IdentityType": identityType,
                        "IdentityName": identityName,
                        "PolicyName": policy.get("PolicyName", "Unknown"),
                        "PolicyArn": policy.get("PolicyArn"),
                        "Action": statement.get("Action"),
                        "Resource": statement.get("Resource")
                            }                     
                    )    
    return findings

def analyze_policy_for_policy_attachment_escalation(policies, identityType, identityName): #IAM_06
    findings = []
    for policy in policies:
        statements = policy['PolicyDocument']['Statement']
        if isinstance(statements, dict):
            statements = [statements]
        for statement in statements:
            if "Action" not in statement or "Resource" not in statement or "Effect" not in statement:
                continue
            target_actions = ["iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:AttachGroupPolicy","iam:PutUserPolicy", "iam:PutRolePolicy", "iam:PutGroupPolicy"]
            for target_action in target_actions:
                if(str(statement.get('Effect'))=="Allow") and analyze_resources(statement.get('Resource'))  and match_action(statement.get('Action'), str(target_action)):
                    findings.append({
                        "RuleID": "IAM_06",
                        "Severity": "CRITICAL",
                        "Title": f"Direct Privilege Escalation via Policy Attachment with {target_action}",
                        "IdentityType": identityType,
                        "IdentityName": identityName,
                        "PolicyName": policy.get("PolicyName", "Unknown"),
                        "PolicyArn": policy.get("PolicyArn"),
                        "Action": statement.get("Action"),
                        "Resource": statement.get("Resource")
                            }                     
                    )    
    return findings

def analyze_access_key_creation_escalation(policies, identityType, identityName): #IAM_07
    findings = []
    for policy in policies:
        statements = policy['PolicyDocument']['Statement']
        if isinstance(statements, dict):
            statements = [statements]
        for statement in statements:
            if "Action" not in statement or "Resource" not in statement or "Effect" not in statement:
                continue
            if(str(statement.get('Effect'))=="Allow") and analyze_resources(statement.get('Resource'))  and match_action(statement.get('Action'), "iam:CreateAccessKey"):
                findings.append({
                        "RuleID": "IAM_07",
                        "Severity": "CRITICAL",
                        "Title": "Privilege Escalation via iam:CreateAccessKey",
                        "IdentityType": identityType,
                        "IdentityName": identityName,
                        "PolicyName": policy.get("PolicyName", "Unknown"),
                        "PolicyArn": policy.get("PolicyArn"),
                        "Action": statement.get("Action"),
                        "Resource": statement.get("Resource")
                            }                     
                    )    
    return findings

def analyze_console_access_escalation(policies, identityType, identityName): #IAM_08
    findings = []
    for policy in policies:
        statements = policy['PolicyDocument']['Statement']
        if isinstance(statements, dict):
            statements = [statements]
        for statement in statements:
            if "Action" not in statement or "Resource" not in statement or "Effect" not in statement:
                continue
            target_actions = ["iam:CreateLoginProfile", "iam:UpdateLoginProfile"]
            for target_action in target_actions:
                if(str(statement.get('Effect'))=="Allow") and analyze_resources(statement.get('Resource'))  and match_action(statement.get('Action'), str(target_action)):
                    findings.append({
                        "RuleID": "IAM_08",
                        "Severity": "CRITICAL",
                        "Title": f"Console Access Privilege Escalation via {target_action}",
                        "IdentityType": identityType,
                        "IdentityName": identityName,
                        "PolicyName": policy.get("PolicyName", "Unknown"),
                        "PolicyArn": policy.get("PolicyArn"),
                        "Action": statement.get("Action"),
                        "Resource": statement.get("Resource")
                            }                     
                    )    
    return findings

def analyze_policy_for_set_policy_version(policies, identityType, identityName): #IAM_09
    findings = []
    for policy in policies:
        statements = policy['PolicyDocument']['Statement']
        if isinstance(statements, dict):
            statements = [statements]
        for statement in statements:
            if "Action" not in statement or "Resource" not in statement or "Effect" not in statement:
                continue
            if(str(statement.get('Effect'))=="Allow") and analyze_resources(statement.get('Resource'))  and match_action(statement.get('Action'), "iam:SetDefaultPolicyVersion"):
                findings.append({
                        "RuleID": "IAM_09",
                        "Severity": "CRITICAL",
                        "Title": "Privilege Escalation via iam:SetDefaultPolicyVersion",
                        "IdentityType": identityType,
                        "IdentityName": identityName,
                        "PolicyName": policy.get("PolicyName", "Unknown"),
                        "PolicyArn": policy.get("PolicyArn"),
                        "Action": statement.get("Action"),
                        "Resource": statement.get("Resource")
                            }                     
                    )    
    return findings  