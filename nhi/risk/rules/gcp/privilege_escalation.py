"""
GCP Non-Human Identity (NHI) Risk Rules.
"""

def analyze_service_account_token_creator(iam_policy):
    findings = []
    if not iam_policy or not isinstance(iam_policy, dict):
        return findings
    bindings = iam_policy.get("bindings") or []
    for binding in bindings:
        if not isinstance(binding, dict):
            continue
        if binding.get("role") == "roles/iam.serviceAccountTokenCreator":
            members = binding.get("members") or []
            for member in members:
                if isinstance(member, str) and member.startswith("serviceAccount:"):
                    sa_email = member.removeprefix("serviceAccount:")
                    findings.append({
                        "RuleID": "GCP_01",
                        "Severity": "CRITICAL",
                        "IdentityType": "ServiceAccount",
                        "IdentityName": sa_email,
                        "Finding": "Privilege Escalation via iam.serviceAccountTokenCreator (Service Account Impersonation)",
                        "Role": "roles/iam.serviceAccountTokenCreator",
                    })
    return findings


def analyze_service_account_key_admin(iam_policy):
    findings = []
    if not iam_policy or not isinstance(iam_policy, dict):
        return findings
    bindings = iam_policy.get("bindings") or []
    for binding in bindings:
        if not isinstance(binding, dict):
            continue
        if binding.get("role") == "roles/iam.serviceAccountKeyAdmin":
            members = binding.get("members") or []
            for member in members:
                if isinstance(member, str) and member.startswith("serviceAccount:"):
                    sa_email = member.removeprefix("serviceAccount:")
                    findings.append({
                        "RuleID": "GCP_02",
                        "Severity": "CRITICAL",
                        "IdentityType": "ServiceAccount",
                        "IdentityName": sa_email,
                        "Finding": "Privilege Escalation via iam.serviceAccountKeyAdmin (Persistent Private Key Creation)",
                        "Role": "roles/iam.serviceAccountKeyAdmin",
                    })
    return findings


def analyze_service_account_user(iam_policy):
    findings = []
    if not iam_policy or not isinstance(iam_policy, dict):
        return findings
    bindings = iam_policy.get("bindings") or []
    for binding in bindings:
        if not isinstance(binding, dict):
            continue
        if binding.get("role") == "roles/iam.serviceAccountUser":
            members = binding.get("members") or []
            for member in members:
                if isinstance(member, str) and member.startswith("serviceAccount:"):
                    sa_email = member.removeprefix("serviceAccount:")
                    findings.append({
                        "RuleID": "GCP_03",
                        "Severity": "HIGH",
                        "IdentityType": "ServiceAccount",
                        "IdentityName": sa_email,
                        "Finding": "Privilege Escalation via iam.serviceAccountUser (Service Account Resource Attachment)",
                        "Role": "roles/iam.serviceAccountUser",
                    })
    return findings


def analyze_iam_security_admin(iam_policy):
    findings = []
    if not iam_policy or not isinstance(iam_policy, dict):
        return findings
    bindings = iam_policy.get("bindings") or []
    for binding in bindings:
        if not isinstance(binding, dict):
            continue
        role = binding.get("role")
        if role in ("roles/iam.securityAdmin", "roles/resourcemanager.projectIamAdmin"):
            members = binding.get("members") or []
            for member in members:
                if isinstance(member, str) and member.startswith("serviceAccount:"):
                    sa_email = member.removeprefix("serviceAccount:")
                    findings.append({
                        "RuleID": "GCP_04",
                        "Severity": "CRITICAL",
                        "IdentityType": "ServiceAccount",
                        "IdentityName": sa_email,
                        "Finding": "Privilege Escalation via Direct IAM Policy Modification (setIamPolicy)",
                        "Role": role,
                    })
    return findings

def analyze_deployment_privesc(iam_policy):
    findings = []
    if not iam_policy or not isinstance(iam_policy, dict):
        return findings
    bindings = iam_policy.get("bindings") or []
    target_roles = ("roles/cloudfunctions.developer", "roles/run.developer")
    for binding in bindings:
        if not isinstance(binding, dict):
            continue
        role = binding.get("role")
        if role in target_roles:
            members = binding.get("members") or []
            for member in members:
                if isinstance(member, str) and member.startswith("serviceAccount:"):
                    sa_email = member.removeprefix("serviceAccount:")
                    findings.append({
                        "RuleID": "GCP_05",
                        "Severity": "HIGH",
                        "IdentityType": "ServiceAccount",
                        "IdentityName": sa_email,
                        "Finding": f"Privilege Escalation via Serverless Workload Deployment ({role})",
                        "Role": role,
                    })
    return findings
