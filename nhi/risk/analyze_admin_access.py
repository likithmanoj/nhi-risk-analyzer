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