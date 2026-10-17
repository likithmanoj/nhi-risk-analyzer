"""
Azure Risk Sub-Runner: RBAC and Service Principal permission evaluations.
"""
from nhi.risk.rules.azure.privilege_escalation import (
    analyze_subscription_owner_contributor,
    analyze_graph_app_role_assignment,
    analyze_vm_contributor_run_command,
    analyze_key_vault_secret_officer,
)
from nhi.risk.rules.azure.credentials import (
    analyze_stale_sp_credentials,
)


def run_azure_checks(azure_data):
    """Sub-runner to execute all Azure RBAC and credential rules against Azure inventory data."""
    findings = []
    role_assignments = azure_data.get("role_assignments", [])
    service_principals = azure_data.get("service_principals", [])

    findings.extend(analyze_subscription_owner_contributor(role_assignments))
    findings.extend(analyze_vm_contributor_run_command(role_assignments))
    findings.extend(analyze_key_vault_secret_officer(role_assignments))
    findings.extend(analyze_graph_app_role_assignment(service_principals))
    findings.extend(analyze_stale_sp_credentials(service_principals))

    return findings
