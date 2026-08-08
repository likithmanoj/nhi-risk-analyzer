from nhi.services.inventory import create_inventory
from nhi.risk.rules.wildcards import analyze_policy, analyze_admin_access
from nhi.risk.rules.credentials import analyze_stale_access_keys, analyze_unused_keys
from nhi.risk.rules.privilege_escalation import (
    analyze_passrole_with_wildcard,                    # IAM_04
    analyze_create_policy_version,                     # IAM_05
    analyze_policy_for_policy_attachment_escalation,  # IAM_06
    analyze_access_key_creation_escalation,             # IAM_07
    analyze_console_access_escalation,                 # IAM_08
)


def run_privilege_escalation_checks(policies, identity_type, identity_name):
    """Sub-runner to execute all privilege escalation rules against a policy list."""
    findings = []
    findings.extend(analyze_passrole_with_wildcard(policies, identity_type, identity_name))
    findings.extend(analyze_create_policy_version(policies, identity_type, identity_name))
    findings.extend(analyze_policy_for_policy_attachment_escalation(policies, identity_type, identity_name))
    findings.extend(analyze_access_key_creation_escalation(policies, identity_type, identity_name))
    findings.extend(analyze_console_access_escalation(policies, identity_type, identity_name))
    return findings


def analyze_inventory():
    response = create_inventory()

    users = response.get("users", [])
    groups = response.get("groups", [])
    roles = response.get("roles", [])

    findings = []

    # ---------------------------------------------------------
    # 1. USER ANALYSIS
    # ---------------------------------------------------------
    for user in users:
        username = user['UserName']
        attached = user.get('AttachedPolicies', [])
        inline = user.get('InlinePolicies', [])
        access_keys = user.get('AccessKeys', [])

        # Policy & Admin Checks
        findings.extend(analyze_policy(attached, "User", username))
        findings.extend(analyze_policy(inline, "User", username))
        findings.extend(analyze_admin_access(attached, "User", username))

        # Credential Checks
        findings.extend(analyze_stale_access_keys(access_keys, username))
        findings.extend(analyze_unused_keys(access_keys, username))

        # Privilege Escalation Checks (IAM_04 through IAM_08)
        findings.extend(run_privilege_escalation_checks(attached, "User", username))
        findings.extend(run_privilege_escalation_checks(inline, "User", username))

    # ---------------------------------------------------------
    # 2. GROUP ANALYSIS
    # ---------------------------------------------------------
    for group in groups:
        group_name = group['GroupName']
        attached = group.get('AttachedPolicies', [])
        inline = group.get('InlinePolicies', [])

        # Policy & Admin Checks
        findings.extend(analyze_policy(attached, "Group", group_name))
        findings.extend(analyze_policy(inline, "Group", group_name))
        findings.extend(analyze_admin_access(attached, "Group", group_name))

        # Privilege Escalation Checks (IAM_04 through IAM_08)
        findings.extend(run_privilege_escalation_checks(attached, "Group", group_name))
        findings.extend(run_privilege_escalation_checks(inline, "Group", group_name))

    # ---------------------------------------------------------
    # 3. ROLE ANALYSIS
    # ---------------------------------------------------------
    for role in roles:
        role_name = role['RoleName']
        attached = role.get('AttachedPolicies', [])
        inline = role.get('InlinePolicies', [])

        # Policy & Admin Checks
        findings.extend(analyze_policy(attached, "Role", role_name))
        findings.extend(analyze_policy(inline, "Role", role_name))
        findings.extend(analyze_admin_access(attached, "Role", role_name))

        # Privilege Escalation Checks (IAM_04 through IAM_08)
        findings.extend(run_privilege_escalation_checks(attached, "Role", role_name))
        findings.extend(run_privilege_escalation_checks(inline, "Role", role_name))

    return findings


if __name__ == "__main__":
    all_findings = analyze_inventory()
    print(all_findings)