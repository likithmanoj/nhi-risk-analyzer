from nhi.services.inventory import create_inventory
from nhi.risk.rules.wildcards import analyze_policy, analyze_admin_access
from nhi.risk.rules.credentials import analyze_stale_access_keys,analyze_unused_keys
from nhi.risk.rules.privilege_escalation import analyze_passrole_with_wildcard


response = create_inventory()

users = response["users"]
groups = response["groups"]
roles = response["roles"]

findings = []

for user in users:
    findings.extend(analyze_policy(user['AttachedPolicies'], "User", user['UserName']))    
    findings.extend(analyze_policy(user['InlinePolicies'], "User", user['UserName']))
    findings.extend(analyze_admin_access(user['AttachedPolicies'], "User", user['UserName']))
    access_keys = user.get('AccessKeys', [])
    findings.extend(analyze_stale_access_keys(access_keys, user['UserName']))
    findings.extend(analyze_unused_keys(access_keys, user['UserName']))
    findings.extend(analyze_passrole_with_wildcard(user['AttachedPolicies'], "User", user['UserName']))
    findings.extend(analyze_passrole_with_wildcard(user['InlinePolicies'], "User", user['UserName']))

for group in groups:
    findings.extend(analyze_policy(group['AttachedPolicies'], "Group", group['GroupName']))
    findings.extend(analyze_policy(group['InlinePolicies'], "Group", group['GroupName']))
    findings.extend(analyze_admin_access(group['AttachedPolicies'], "Group", group['GroupName']))
    findings.extend(analyze_passrole_with_wildcard(group['AttachedPolicies'], "Group", group['GroupName']))
    findings.extend(analyze_passrole_with_wildcard(group['InlinePolicies'], "Group", group['GroupName']))

for role in roles:
    findings.extend(analyze_policy(role['AttachedPolicies'],"Role", role['RoleName']))
    findings.extend(analyze_policy(role['InlinePolicies'],"Role", role['RoleName']))
    findings.extend(analyze_admin_access(role['AttachedPolicies'],"Role", role['RoleName']))
    findings.extend(analyze_passrole_with_wildcard(role['AttachedPolicies'], "Role", role['RoleName']))
    findings.extend(analyze_passrole_with_wildcard(role['InlinePolicies'], "Role", role['RoleName']))

print(findings)