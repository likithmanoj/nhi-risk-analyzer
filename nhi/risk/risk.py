import argparse
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
from nhi.remediation.dispatch import dispatch_remediation
from nhi.risk.rules.tags import analyze_mandatory_tags
from nhi.risk.rules.trust_policy import analyze_trust_policy #IAM_10


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


    for role in roles:
        role_name = role['RoleName']
        attached = role.get('AttachedPolicies', [])
        inline = role.get('InlinePolicies', [])        
        findings.extend(analyze_policy(attached, "Role", role_name))
        findings.extend(analyze_policy(inline, "Role", role_name))
        findings.extend(analyze_admin_access(attached, "Role", role_name))        
        findings.extend(run_privilege_escalation_checks(attached, "Role", role_name))
        findings.extend(run_privilege_escalation_checks(inline, "Role", role_name))
        findings.extend(analyze_mandatory_tags(role, "Role"))
        trust_policy = role.get("TrustPolicy", {})
        findings.extend(analyze_trust_policy(trust_policy, role_name))

    return findings


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NHI Risk Analyzer & Remediation Engine for AWS")
    
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate remediation actions without making changes in AWS",
    )
    group.add_argument(
        "--remediate",
        action="store_true",
        help="Execute live remediation against detected findings",
    )
    
    args = parser.parse_args()

    print("[*] Running inventory and risk evaluation...")
    all_findings = analyze_inventory()
    print(f"[*] Findings detected: {len(all_findings)}")   
    if args.remediate:
        print("[!] Executing LIVE remediation...")
        stats = dispatch_remediation(all_findings, dry_run=False)
        print("Live Remediation Stats:", stats)
    elif args.dry_run:
        print("[*] Executing DRY RUN simulation...")
        stats = dispatch_remediation(all_findings, dry_run=True)
        print("Dry Run Stats:", stats)

    else:
        print("[*] Scan complete. (Pass --dry-run to simulate containment or --remediate to execute live)")
