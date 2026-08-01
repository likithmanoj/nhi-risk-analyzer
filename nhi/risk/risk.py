from nhi.services.inventory import create_inventory

response = create_inventory()

users = response["users"]
groups = response["groups"]
roles = response["roles"]

findings = []

for user in users:
    for policy in user["AttachedPolicies"]:
        for statement in policy["PolicyDocument"]["Statement"]:

            # Skip statements without an Action
            if "Action" not in statement:
                continue

            actions = statement["Action"]

            if isinstance(actions, str):
                if "*" in actions:
                    findings.append({
                        "IdentityType": "User",
                        "IdentityName": user["UserName"],
                        "PolicyName": policy["PolicyName"],
                        "Action": actions,
                        "Finding": "Wildcard Action",
                        "Severity": "HIGH"
                    })

            elif isinstance(actions, list):
                for action in actions:
                    if "*" in action:
                        findings.append({
                            "IdentityType": "User",
                            "IdentityName": user["UserName"],
                            "PolicyName": policy["PolicyName"],
                            "Action": action,
                            "Finding": "Wildcard Action",
                            "Severity": "HIGH"
                        })
                        break

    for policy in user["InlinePolicies"]:
            for statement in policy["PolicyDocument"]["Statement"]:
    
                # Skip statements without an Action
                if "Action" not in statement:
                    continue
    
                actions = statement["Action"]
    
                if isinstance(actions, str):
                    if "*" in actions:
                        findings.append({
                            "IdentityType": "User",
                            "IdentityName": user["UserName"],
                            "PolicyName": policy["PolicyName"],
                            "Action": actions,
                            "Finding": "Wildcard Action",
                            "Severity": "HIGH"
                        })
    
                elif isinstance(actions, list):
                    for action in actions:
                        if "*" in action:
                            findings.append({
                                "IdentityType": "User",
                                "IdentityName": user["UserName"],
                                "PolicyName": policy["PolicyName"],
                                "Action": action,
                                "Finding": "Wildcard Action",
                                "Severity": "HIGH"
                            })
                            break

for group in groups:
    for policy in group["AttachedPolicies"]:
        for statement in policy["PolicyDocument"]["Statement"]:

            # Skip statements without an Action
            if "Action" not in statement:
                continue

            actions = statement["Action"]

            if isinstance(actions, str):
                if "*" in actions:
                    findings.append({
                        "IdentityType": "Group",
                        "IdentityName": group["GroupName"],
                        "PolicyName": policy["PolicyName"],
                        "Action": actions,
                        "Finding": "Wildcard Action",
                        "Severity": "HIGH"
                    })

            elif isinstance(actions, list):
                for action in actions:
                    if "*" in action:
                        findings.append({
                            "IdentityType": "Group",
                            "IdentityName": group["GroupName"],
                            "PolicyName": policy["PolicyName"],
                            "Action": action,
                            "Finding": "Wildcard Action",
                            "Severity": "HIGH"
                        })
                        break

    for policy in group["InlinePolicies"]:
            for statement in policy["PolicyDocument"]["Statement"]:
    
                # Skip statements without an Action
                if "Action" not in statement:
                    continue
    
                actions = statement["Action"]
    
                if isinstance(actions, str):
                    if "*" in actions:
                        findings.append({
                            "IdentityType": "Group",
                            "IdentityName": group["GroupName"],
                            "PolicyName": policy["PolicyName"],
                            "Action": actions,
                            "Finding": "Wildcard Action",
                            "Severity": "HIGH"
                        })
    
                elif isinstance(actions, list):
                    for action in actions:
                        if "*" in action:
                            findings.append({
                                "IdentityType": "Group",
                                "IdentityName": group["GroupName"],
                                "PolicyName": policy["PolicyName"],
                                "Action": action,
                                "Finding": "Wildcard Action",
                                "Severity": "HIGH"
                            })
                            break
for role in roles:
    for policy in role["AttachedPolicies"]:
        for statement in policy["PolicyDocument"]["Statement"]:

            # Skip statements without an Action
            if "Action" not in statement:
                continue

            actions = statement["Action"]

            if isinstance(actions, str):
                if "*" in actions:
                    findings.append({
                        "IdentityType": "Role",
                        "IdentityName": role["RoleName"],
                        "PolicyName": policy["PolicyName"],
                        "Action": actions,
                        "Finding": "Wildcard Action",
                        "Severity": "HIGH"
                    })

            elif isinstance(actions, list):
                for action in actions:
                    if "*" in action:
                        findings.append({
                            "IdentityType": "Role",
                            "IdentityName": role["RoleName"],
                            "PolicyName": policy["PolicyName"],
                            "Action": action,
                            "Finding": "Wildcard Action",
                            "Severity": "HIGH"
                        })
                        break
    for policy in role["InlinePolicies"]:
            for statement in policy["PolicyDocument"]["Statement"]:
    
                # Skip statements without an Action
                if "Action" not in statement:
                    continue
    
                actions = statement["Action"]
    
                if isinstance(actions, str):
                    if "*" in actions:
                        findings.append({
                            "IdentityType": "Role",
                            "IdentityName": role["RoleName"],
                            "PolicyName": policy["PolicyName"],
                            "Action": actions,
                            "Finding": "Wildcard Action",
                            "Severity": "HIGH"
                        })
    
                elif isinstance(actions, list):
                    for action in actions:
                        if "*" in action:
                            findings.append({
                                "IdentityType": "Role",
                                "IdentityName": role["RoleName"],
                                "PolicyName": policy["PolicyName"],
                                "Action": action,
                                "Finding": "Wildcard Action",
                                "Severity": "HIGH"
                            })
                            break

print(findings)