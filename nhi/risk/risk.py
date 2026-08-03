from nhi.services.inventory import create_inventory
from nhi.risk.analyze_policy import analyze_policy
from nhi.risk.analyze_admin_access import analyze_admin_access

response = create_inventory()

users = response["users"]
groups = response["groups"]
roles = response["roles"]

findings = []

for user in users:
    findings.extend(analyze_policy(user['AttachedPolicies'], "User", user['UserName']))    
    findings.extend(analyze_policy(user['InlinePolicies'], "User", user['UserName']))
    findings.extend(analyze_admin_access(user['AttachedPolicies'], "User", user['UserName']))

for group in groups:
    findings.extend(analyze_policy(group['AttachedPolicies'], "Group", group['GroupName']))
    findings.extend(analyze_policy(group['InlinePolicies'], "Group", group['GroupName']))
    findings.extend(analyze_admin_access(group['AttachedPolicies'], "Group", group['GroupName']))

for role in roles:
    findings.extend(analyze_policy(role['AttachedPolicies'],"Role", role['RoleName']))
    findings.extend(analyze_policy(role['InlinePolicies'],"Role", role['RoleName']))
    findings.extend(analyze_admin_access(role['AttachedPolicies'],"Role", role['RoleName']))

print(findings)