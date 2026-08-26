GLOBAL_NON_RESOURCE_ACTIONS = {
    "sts:getcalleridentity",
    "iam:getaccountsummary",
    "iam:generatecredentialreport",
    "ec2:getaccountattributes",
    "cloudtrail:lookupevents",
}

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

def analyze_actions(actions):
    action_findings = []
    if isinstance(actions, str):
        if "*" in actions:
            action_findings.append({"Action": actions})               
            
                       
    elif isinstance(actions, list):
        action_findings = []
        for action in actions:
            if "*" in action:
                action_findings.append({"Action": action})
                break
    return action_findings

def analyze_resources(resources):
    resource_findings = []
    if isinstance(resources, str):
        resources_list = [resources]
    elif isinstance(resources, list):
        resources_list = resources
    else:
        return resource_findings
    
    for resource in resources_list:
        classification = classify_resources(resource)
        if classification in ("UNCONSTRAINED", "SCOPED_PREFIX"):
            resource_findings.append({"Resource": resource, "Type": classification})
            break
    return resource_findings

def classify_resources(resource):
    if not isinstance(resource, str):
        return None
    if resource == "*" or resource == "arn:aws:*:*:*:*":
         return "UNCONSTRAINED"
    if "*" in resource:
        if resource.startswith("arn:aws:") and not resource.startswith("arn:aws:*:"):
            return "SCOPED_PREFIX"
        return "UNCONSTRAINED"
    return "SPECIFIC"

def is_non_resource_action(action: str) -> bool:
    if not isinstance(action, str):
        return False
    
    action_lower = action.strip().lower()
    
    if action_lower.endswith(":*") or action_lower == "*":
        return False
    
    if action_lower in GLOBAL_NON_RESOURCE_ACTIONS:
        return True
    
    if ":" in action_lower:
        _service, api = action_lower.split(":", 1)
        if api.startswith("describe") or api.startswith("list"):
            return True
            
    return False

def are_all_actions_non_resource(actions) -> bool:
    if isinstance(actions, str):
        actions = [actions]
    elif not isinstance(actions, list) or not actions:
        return False
    
    return all(is_non_resource_action(act) for act in actions)
