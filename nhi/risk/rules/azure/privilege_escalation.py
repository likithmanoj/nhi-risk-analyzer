"""
Azure Privilege Escalation Rules.
"""

def analyze_subscription_owner_contributor(role_assignments):
    findings = []
    if not isinstance(role_assignments, list):
        return findings

    for assignment in role_assignments:
        if not isinstance(assignment, dict):
            continue
        properties = assignment.get('properties') if isinstance(assignment.get('properties'), dict) else assignment
        role = properties.get("roleDefinitionName")
        scope = properties.get("scope") or ""

        if properties.get('principalType') == "ServicePrincipal" and role in ["Owner", "User Access Administrator"] and scope.startswith("/subscriptions/") and "/resourceGroups/" not in scope:
            findings.append({
                "RuleID": "AZURE_01",
                "Severity": "CRITICAL",
                "IdentityType": "ServicePrincipal",
                "IdentityName": properties.get("principalId"),
                "Finding": f"Subscription Takeover via Service Principal assigned '{role}' at Subscription Scope",
                "Role": role,
                "Resource": scope,
            })

    return findings


def analyze_graph_app_role_assignment(service_principals):
    findings = []
    if not isinstance(service_principals, list):
        return findings

    dangerous_permissions = {
        "AppRoleAssignment.ReadWrite.All",
        "Application.ReadWrite.All",
        "RoleAssignment.ReadWrite.All",
        "Directory.ReadWrite.All",
    }

    for sp in service_principals:
        if not isinstance(sp, dict):
            continue
        sp_id = sp.get("appId") or sp.get("id") or sp.get("principalId")
        sp_name = sp.get("displayName") or sp.get("name") or sp_id

        permissions = sp.get("apiPermissions") or sp.get("appRoleAssignments") or []
        for perm in permissions:
            perm_name = perm if isinstance(perm, str) else (perm.get("value") or perm.get("role") or perm.get("permission"))
            if perm_name in dangerous_permissions:
                findings.append({
                    "RuleID": "AZURE_02",
                    "Severity": "CRITICAL",
                    "IdentityType": "ServicePrincipal",
                    "IdentityName": sp_name,
                    "Finding": f"Entra ID Privilege Escalation via Microsoft Graph permission '{perm_name}'",
                    "Role": perm_name,
                    "Resource": "Microsoft.Graph",
                })

    return findings


def analyze_vm_contributor_run_command(role_assignments):
    findings = []
    if not isinstance(role_assignments, list):
        return findings

    target_roles = ("Virtual Machine Contributor", "Virtual Machine Administrator Login")
    for assignment in role_assignments:
        if not isinstance(assignment, dict):
            continue
        properties = assignment.get("properties") if isinstance(assignment.get("properties"), dict) else assignment
        role = properties.get("roleDefinitionName")
        scope = properties.get("scope") or ""

        if properties.get("principalType") == "ServicePrincipal" and role in target_roles:
            findings.append({
                "RuleID": "AZURE_03",
                "Severity": "HIGH",
                "IdentityType": "ServicePrincipal",
                "IdentityName": properties.get("principalId"),
                "Finding": f"Privilege Escalation via {role} (Remote Code Execution via RunCommand)",
                "Role": role,
                "Resource": scope,
            })

    return findings


def analyze_key_vault_secret_officer(role_assignments):
    findings = []
    if not isinstance(role_assignments, list):
        return findings

    target_roles = ("Key Vault Administrator", "Key Vault Secrets Officer")
    for assignment in role_assignments:
        if not isinstance(assignment, dict):
            continue
        properties = assignment.get("properties") if isinstance(assignment.get("properties"), dict) else assignment
        role = properties.get("roleDefinitionName")
        scope = properties.get("scope") or ""

        if properties.get("principalType") == "ServicePrincipal" and role in target_roles:
            findings.append({
                "RuleID": "AZURE_04",
                "Severity": "HIGH",
                "IdentityType": "ServicePrincipal",
                "IdentityName": properties.get("principalId"),
                "Finding": f"Privilege Escalation via {role} (Key Vault Data Plane Secret Harvesting)",
                "Role": role,
                "Resource": scope,
            })

    return findings