def analyze_admin_access(policies,identityType,identityName):
    findings = [] #local findings
    for policy in policies:
        if policy['PolicyArn'] == "arn:aws:iam::aws:policy/AdministratorAccess":
            findings.append({
                "IdentityType":identityType,
                "IdentityName": identityName,
                "PolicyName" : policy['PolicyName'],
                "Finding": "AdministratorAccess Managed Policy Attached",
                "Severity": "CRITICAL"})
    return findings

def analyze_policy(policies,identityType,identityName):
    findings = []
    
    for policy in policies:
        for statement in policy["PolicyDocument"]["Statement"]:

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
                    "IdentityType":identityType,
                    "IdentityName": identityName,
                    "PolicyName" : policy['PolicyName'],
                    "Finding": "Administrator-Equivalent Permissions",
                    "Resource": resources_findings[0]["Resource"],
                    "Action": actions_findings[0]["Action"],
                    "Severity": "CRITICAL"})
            elif resources_findings:
                for resource in resources_findings:
                    findings.append({
                    "IdentityType":identityType,
                    "IdentityName": identityName,
                    "PolicyName" : policy['PolicyName'],
                    "Finding": "Wildcard Resources",
                    "Resource": resource["Resource"],
                    "Severity": "HIGH"})
            elif actions_findings:
                for action in actions_findings:
                    findings.append(
                    {
                       "IdentityType":identityType,
                       "IdentityName": identityName,
                        "PolicyName" : policy['PolicyName'],
                        "Finding": "Wildcard Actions",
                        "Action": action["Action"],
                        "Severity": "HIGH" 
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
            if "*" in resources:
                resource_findings.append({"Resource": resources})
                           
    elif isinstance(resources, list):
        for resource in resources:
            if "*" in resource:
                resource_findings.append({"Resource": resource})
                break
    return resource_findings

def analyze_admin_access(policies,identityType,identityName):
    findings = [] #local findings
    for policy in policies:
        if policy['PolicyName'] == "AdministratorAccess":
            findings.append({
                "IdentityType":identityType,
                "IdentityName": identityName,
                "PolicyName" : policy['PolicyName'],
                "Finding": "Wildcard Resources",
                "Severity": "HIGH"})
    return findings
