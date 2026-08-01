def analyze_policy(policies,identityType,identityName):
    findings = []
    for policy in policies:
            for statement in policy["PolicyDocument"]["Statement"]:
    
                # Skip statements without an Action
                if "Action" not in statement:
                    continue
    
                actions = statement["Action"]
    
                if isinstance(actions, str):
                    if "*" in actions:
                        findings.append({
                            "IdentityType":identityType,
                            "IdentityName": identityName,
                            "PolicyName" : policy['PolicyName'],
                            "Action": actions,
                            "Finding": "Wildcard Action",
                            "Severity": "HIGH"
                        })
    
                elif isinstance(actions, list):
                    for action in actions:
                        if "*" in action:
                            findings.append({
                                "IdentityType":identityType,
                                "IdentityName": identityName,
                                "PolicyName" : policy['PolicyName'],
                                "Action": action,
                                "Finding": "Wildcard Action",
                                "Severity": "HIGH"
                            })
                            break

    return findings