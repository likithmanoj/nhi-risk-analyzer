def analyze_passrole_with_wildcard(policies,identityType,identityName): #IAM_04
    findings = []
    for policy in policies:
            statements = policy["PolicyDocument"]["Statement"]
            if isinstance(policy["PolicyDocument"]["Statement"], dict):
                statements = [statements]
            for statement in statements:    
                    if "Action" not in statement or "Resource" not in statement or "Effect" not in statement:
                        continue
                    if(str(statement.get('Effect'))=="Allow") and analyze_resources_for_privilege_escalation(statement.get('Resource')) and analyze_actions_for_privilege_escalation(statement.get('Action'), "iam:PassRole") and not has_passed_to_service_condition(statement.get("Condition")):
                        findings.append(
                              {
                            "RuleID": "IAM_04",
                            "Severity": "HIGH",
                            "Title": "Privilege Escalation via iam:PassRole granted with Wildcard Resource",
                            "IdentityType": identityType,
                            "IdentityName": identityName,
                            "PolicyName": policy.get("PolicyName", "Unknown"),
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
            if(str(statement.get('Effect'))=="Allow") and analyze_resources_for_privilege_escalation(statement.get('Resource'))  and analyze_actions_for_privilege_escalation(statement.get('Action'), "iam:CreatePolicyVersion"):
                findings.append({
                        "RuleID": "IAM_05",
                        "Severity": "CRITICAL",
                        "Title": "Privilege Escalation via iam:CreatePolicyVersion",
                        "IdentityType": identityType,
                        "IdentityName": identityName,
                        "PolicyName": policy.get("PolicyName", "Unknown"),
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
                if(str(statement.get('Effect'))=="Allow") and analyze_resources_for_privilege_escalation(statement.get('Resource'))  and analyze_actions_for_privilege_escalation(statement.get('Action'), str(target_action)):
                    findings.append({
                        "RuleID": "IAM_06",
                        "Severity": "CRITICAL",
                        "Title": f"Direct Privilege Escalation via Policy Attachment with {target_action}",
                        "IdentityType": identityType,
                        "IdentityName": identityName,
                        "PolicyName": policy.get("PolicyName", "Unknown"),
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
            if(str(statement.get('Effect'))=="Allow") and analyze_resources_for_privilege_escalation(statement.get('Resource'))  and analyze_actions_for_privilege_escalation(statement.get('Action'), "iam:CreateAccessKey"):
                findings.append({
                        "RuleID": "IAM_07",
                        "Severity": "CRITICAL",
                        "Title": "Privilege Escalation via iam:CreateAccessKey",
                        "IdentityType": identityType,
                        "IdentityName": identityName,
                        "PolicyName": policy.get("PolicyName", "Unknown"),
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
                if(str(statement.get('Effect'))=="Allow") and analyze_resources_for_privilege_escalation(statement.get('Resource'))  and analyze_actions_for_privilege_escalation(statement.get('Action'), str(target_action)):
                    findings.append({
                        "RuleID": "IAM_08",
                        "Severity": "CRITICAL",
                        "Title": f"Console Access Privilege Escalation via {target_action}",
                        "IdentityType": identityType,
                        "IdentityName": identityName,
                        "PolicyName": policy.get("PolicyName", "Unknown"),
                        "Action": statement.get("Action"),
                        "Resource": statement.get("Resource")
                            }                     
                    )    
    return findings
  

def analyze_actions_for_privilege_escalation(actions, check): # check only accepts string, its only a helper
    action_findings = []
    if isinstance(actions, str):
            if "*" in actions or str(check) in actions or "iam:*" in actions:
                action_findings.append({"Action": actions})               
                
                           
    elif isinstance(actions, list):
        action_findings = []
        for action in actions:
            if "*" in action or str(check) in action or "iam:*" in action:
                action_findings.append({"Action": action})
    
    return action_findings


def analyze_resources_for_privilege_escalation(resources):
    resource_findings = []
    if isinstance(resources, str):
            if "*" in resources:
                resource_findings.append({"Resource": resources})
                           
    elif isinstance(resources, list):
        for resource in resources:
            if "*" in resource:
                resource_findings.append({"Resource": resource})
                break
    return resource_findings

def has_passed_to_service_condition(condition_block):
    if not condition_block or not isinstance(condition_block, dict):
        return False

    # Loop through operator keys (e.g., 'StringEquals', 'StringLike')
    for operator, criteria in condition_block.items():
        if isinstance(criteria, dict) and "iam:PassedToService" in criteria:
            return True

    return False