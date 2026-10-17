"""
AWS Risk Sub-Runner: Identity traversal, policy evaluation, and enrichment.
"""
from nhi.risk.rules.aws.wildcards import (
    analyze_policy,
    analyze_admin_access,
)
from nhi.risk.rules.aws.credentials import (
    analyze_stale_access_keys,
    analyze_unused_keys,
)
from nhi.risk.rules.aws.privilege_escalation import (
    analyze_passrole_with_wildcard,
    analyze_create_policy_version,
    analyze_policy_for_policy_attachment_escalation,
    analyze_access_key_creation_escalation,
    analyze_console_access_escalation,
    analyze_policy_for_set_policy_version,
)
from nhi.risk.rules.aws.data_perimeter import (
    analyze_policy_for_s3_exfiltration,
    analyze_policy_for_kms_decryption,
)
from nhi.risk.rules.aws.resource_protection import (
    analyze_policy_for_defense_evasion,
)
from nhi.risk.rules.aws.tags import analyze_mandatory_tags
from nhi.risk.rules.aws.trust_policy import analyze_trust_policy


def run_privilege_escalation_checks(policies, identity_type, identity_name):
    """Sub-runner to execute all privilege escalation rules against a policy list."""
    findings = []
    findings.extend(analyze_passrole_with_wildcard(policies, identity_type, identity_name))
    findings.extend(analyze_create_policy_version(policies, identity_type, identity_name))
    findings.extend(analyze_policy_for_policy_attachment_escalation(policies, identity_type, identity_name))
    findings.extend(analyze_access_key_creation_escalation(policies, identity_type, identity_name))
    findings.extend(analyze_console_access_escalation(policies, identity_type, identity_name))
    findings.extend(analyze_policy_for_set_policy_version(policies, identity_type, identity_name))
    return findings


def run_resource_protection_checks(policies, identity_type, identity_name):
    """Sub-runner to execute data perimeter and defense evasion rules against a policy list."""
    findings = []
    findings.extend(analyze_policy_for_s3_exfiltration(policies, identity_type, identity_name))
    findings.extend(analyze_policy_for_defense_evasion(policies, identity_type, identity_name))
    findings.extend(analyze_policy_for_kms_decryption(policies, identity_type, identity_name))
    return findings


def is_aws_managed_policy(policy_arn):
    return bool(policy_arn and policy_arn.startswith("arn:aws:iam::aws:policy/"))


def enrich_findings_for_aws_managed_policies(findings):
    for finding in findings:
        arn = finding.get("PolicyArn")
        if arn:
            is_aws_managed = is_aws_managed_policy(arn)
            finding["RemediationEligible"] = not is_aws_managed
            if is_aws_managed:
                finding["RemediationNote"] = (
                    "AWS-managed policy — cannot be rewritten. Detach or replace with a customer-managed equivalent."
                )
    return findings


def run_aws_checks(aws_data):
    """Sub-runner to execute all AWS IAM identity and policy rules against AWS inventory data."""
    users = aws_data.get("users", [])
    groups = aws_data.get("groups", [])
    roles = aws_data.get("roles", [])

    findings = []

    for user in users:
        username = user['UserName']
        attached = user.get('AttachedPolicies', [])
        inline = user.get('InlinePolicies', [])
        access_keys = user.get('AccessKeys', [])
        findings.extend(analyze_policy(attached, "User", username))
        findings.extend(analyze_policy(inline, "User", username))
        findings.extend(analyze_admin_access(attached, "User", username))
        findings.extend(analyze_stale_access_keys(access_keys, username))
        findings.extend(analyze_unused_keys(access_keys, username))
        findings.extend(run_privilege_escalation_checks(attached, "User", username))
        findings.extend(run_privilege_escalation_checks(inline, "User", username))
        findings.extend(run_resource_protection_checks(attached, "User", username))
        findings.extend(run_resource_protection_checks(inline, "User", username))
        findings.extend(analyze_mandatory_tags(user, "User"))

    for group in groups:
        group_name = group['GroupName']
        attached = group.get('AttachedPolicies', [])
        inline = group.get('InlinePolicies', [])
        findings.extend(analyze_policy(attached, "Group", group_name))
        findings.extend(analyze_policy(inline, "Group", group_name))
        findings.extend(analyze_admin_access(attached, "Group", group_name))
        findings.extend(run_privilege_escalation_checks(attached, "Group", group_name))
        findings.extend(run_privilege_escalation_checks(inline, "Group", group_name))
        findings.extend(run_resource_protection_checks(attached, "Group", group_name))
        findings.extend(run_resource_protection_checks(inline, "Group", group_name))

    for role in roles:
        role_name = role['RoleName']
        attached = role.get('AttachedPolicies', [])
        inline = role.get('InlinePolicies', [])
        findings.extend(analyze_policy(attached, "Role", role_name))
        findings.extend(analyze_policy(inline, "Role", role_name))
        findings.extend(analyze_admin_access(attached, "Role", role_name))
        findings.extend(run_privilege_escalation_checks(attached, "Role", role_name))
        findings.extend(run_privilege_escalation_checks(inline, "Role", role_name))
        findings.extend(run_resource_protection_checks(attached, "Role", role_name))
        findings.extend(run_resource_protection_checks(inline, "Role", role_name))
        findings.extend(analyze_mandatory_tags(role, "Role"))
        trust_policy = role.get("TrustPolicy", {})
        findings.extend(analyze_trust_policy(trust_policy, role_name))

    findings = enrich_findings_for_aws_managed_policies(findings)

    return findings
