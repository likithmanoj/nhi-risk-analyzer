"""
GCP Risk Sub-Runner: Project IAM and Service Account key evaluations.
"""
from nhi.risk.rules.gcp.privilege_escalation import (
    analyze_service_account_token_creator,
    analyze_service_account_key_admin,
    analyze_service_account_user,
    analyze_iam_security_admin,
    analyze_deployment_privesc,
)
from nhi.risk.rules.gcp.credentials import (
    analyze_stale_service_account_keys,
)


def run_gcp_checks(gcp_data):
    """Sub-runner to execute all GCP IAM and Service Account rules against GCP inventory data."""
    findings = []
    iam_policy = gcp_data.get("iam_policy", {})
    service_accounts = gcp_data.get("service_accounts", [])

    findings.extend(analyze_service_account_token_creator(iam_policy))
    findings.extend(analyze_service_account_key_admin(iam_policy))
    findings.extend(analyze_service_account_user(iam_policy))
    findings.extend(analyze_iam_security_admin(iam_policy))
    findings.extend(analyze_deployment_privesc(iam_policy))
    findings.extend(analyze_stale_service_account_keys(service_accounts))

    return findings
