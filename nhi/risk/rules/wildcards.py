from nhi.risk.helpers import (
    GLOBAL_NON_RESOURCE_ACTIONS,
    analyze_actions,
    analyze_resources,
    are_all_actions_non_resource,
)

def analyze_admin_access(policies,identityType,identityName):
    findings = []
    for policy in policies:
        if policy['PolicyArn'] == "arn:aws:iam::aws:policy/AdministratorAccess":
            findings.append({
                "RuleID": "IAM_03",
                "Severity": "CRITICAL",
                "IdentityType":identityType,
                "IdentityName": identityName,
                "PolicyName" : policy['PolicyName'],
                "Finding": "AdministratorAccess Managed Policy Attached",
                })
    return findings

def analyze_policy(policies,identityType,identityName):
    findings = []
    
    for policy in policies:
        if(policy.get("PolicyArn") and policy.get('PolicyArn').startswith("arn:aws:iam::aws:policy/")):
             continue
        statements = policy["PolicyDocument"]["Statement"]
        if isinstance(statements, dict):
                        statements = [statements]
        for statement in statements:
            actions = []
            resources = []
            if "Action" not in statement and "Resource" not in statement:
                continue

            if "Action" in statement:           
                actions = statement["Action"]
            actions_findings = analyze_actions(actions)
            if "Resource" in statement:
                resources = statement["Resource"]
            resources_findings = analyze_resources(resources)
            if not actions_findings and not resources_findings:
                continue
            if actions_findings and resources_findings:
                    findings.append({
                    "RuleID": "IAM_03",
                    "Severity": "CRITICAL",
                    "IdentityType":identityType,
                    "IdentityName": identityName,
                    "PolicyName" : policy['PolicyName'],
                    "Finding": "Administrator-Equivalent Permissions",
                    "Resource": resources_findings[0]["Resource"],
                    "Action": actions_findings[0]["Action"],
                    })
            elif resources_findings:
                if are_all_actions_non_resource(actions):
                    continue
                for resource in resources_findings:
                    is_scoped = resource.get("Type") == "SCOPED_PREFIX"
                    findings.append({
                    "RuleID": "IAM_02",
                    "Severity": "LOW" if is_scoped else "HIGH",
                    "IdentityType": identityType,
                    "IdentityName": identityName,
                    "PolicyName": policy['PolicyName'],
                    "Finding": "Scoped Wildcard Resource Path" if is_scoped else "Wildcard Resources",
                    "Resource": resource["Resource"],
                    })
            elif actions_findings:
                for action in actions_findings:
                    findings.append(
                    {  
                        "RuleID": "IAM_01",
                        "Severity": "HIGH",
                       "IdentityType":identityType,
                       "IdentityName": identityName,
                        "PolicyName" : policy['PolicyName'],
                        "Finding": "Wildcard Actions",
                        "Action": action["Action"],
                    })
                  

    return findings