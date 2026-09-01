from nhi.risk.helpers import (
    GLOBAL_NON_RESOURCE_ACTIONS,
    analyze_actions,
    analyze_resources,
    are_all_actions_non_resource,
)

KNOWN_DANGEROUS_MANAGED_POLICIES = {
    "arn:aws:iam::aws:policy/AdministratorAccess": "AdministratorAccess Managed Policy Attached",
    "arn:aws:iam::aws:policy/IAMFullAccess": "IAMFullAccess Managed Policy Attached (privilege escalation primitive)",
    "arn:aws:iam::aws:policy/PowerUserAccess": "PowerUserAccess Managed Policy Attached",
}

def analyze_admin_access(policies, identityType, identityName):
    findings = []
    for policy in policies:
        arn = policy.get("PolicyArn")
        if arn in KNOWN_DANGEROUS_MANAGED_POLICIES:
            findings.append({
                "RuleID": "IAM_03",
                "Severity": "CRITICAL",
                "IdentityType": identityType,
                "IdentityName": identityName,
                "PolicyName": policy.get("PolicyName"),
                "PolicyArn": arn,
                "Finding": KNOWN_DANGEROUS_MANAGED_POLICIES[arn]
            })
    return findings

def analyze_policy(policies,identityType,identityName):
    findings = []
    
    for policy in policies:
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
                    "PolicyArn": policy.get("PolicyArn"),
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
                    "PolicyArn": policy.get("PolicyArn"),
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
                        "PolicyArn": policy.get("PolicyArn"),
                        "Finding": "Wildcard Actions",
                        "Action": action["Action"],
                    })
                  

    return findings