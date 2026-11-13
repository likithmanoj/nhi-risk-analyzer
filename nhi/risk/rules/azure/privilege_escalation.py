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
    dangerous_roles_map = {
        "06b708a9-e830-4db3-a914-8e69da51d44f": "AppRoleAssignment.ReadWrite.All",
        "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9": "Application.ReadWrite.All",
        "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8": "RoleManagement.ReadWrite.Directory",
        "df021288-bdef-4463-88db-98f22de89214": "User.ReadWrite.All",
        "approleassignment.readwrite.all": "AppRoleAssignment.ReadWrite.All",
        "application.readwrite.all": "Application.ReadWrite.All",
        "rolemanagement.readwrite.directory": "RoleManagement.ReadWrite.Directory",
        "roleassignment.readwrite.all": "RoleAssignment.ReadWrite.All",
        "directory.readwrite.all": "Directory.ReadWrite.All",
        "user.readwrite.all": "User.ReadWrite.All",
    }
    for sp in service_principals:
        if not isinstance(sp, dict):
            continue
        sp_id = sp.get("appId") or sp.get("id") or sp.get("principalId")
        sp_name = sp.get("displayName") or sp.get("name") or sp_id
        permissions = sp.get("apiPermissions") or sp.get("appRoleAssignments") or []
        for perm in permissions:
            if not perm:
                continue
            raw_target = perm if isinstance(perm, str) else (
                perm.get("appRoleId") or perm.get("value") or perm.get("role") or perm.get("permission") or ""
            )
            target_key = str(raw_target).strip().lower()
            matched_role = dangerous_roles_map.get(target_key)
            if matched_role:
                findings.append({
                    "RuleID": "AZURE_02",
                    "Severity": "CRITICAL",
                    "IdentityType": "ServicePrincipal",
                    "IdentityName": sp_name,
                    "Finding": f"Entra ID Privilege Escalation via Microsoft Graph permission '{matched_role}'",
                    "Role": matched_role,
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