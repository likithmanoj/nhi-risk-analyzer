import logging
from nhi.remediation.dispatch import dispatch_remediation

# Configure root logger so we can observe log output from dispatch and handlers
logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

def test_remediation_dispatch():
    mock_findings = [
        # Case 1: Valid IAM_11 finding -> Should pass payload guard and simulate remediation
        {
            "RuleID": "IAM_11",
            "IdentityType": "user",
            "IdentityName": "app-service-user",
            "TargetID": "AKIA1111111111EXAMPLE",
            "Description": "Unused access key older than 90 days"
        },
        # Case 2: Malformed finding -> Missing TargetID; should trigger payload guard and return False
        {
            "RuleID": "IAM_11",
            "IdentityType": "user",
            "IdentityName": "broken-user-payload",
            "Description": "Missing TargetID field"
        },
        # Case 3: Exemption check -> Ensure IdentityName or Rule matches an entry in your nhi-ignore.yaml
        {
            "RuleID": "IAM_11",
            "IdentityType": "user",
            "IdentityName": "pam-suite-admin",  # Ensure this or rule IAM_11 exists in nhi-ignore.yaml to test skipping
            "TargetID": "AKIA2222222222EXAMPLE",
            "Description": "Exempted user account"
        }
    ]

    print("\n--- Executing dispatch_remediation (DRY RUN) ---")
    metrics = dispatch_remediation(mock_findings, dry_run=True)
    
    print("\n--- Final Metrics Summary ---")
    print(metrics)

if __name__ == "__main__":
    test_remediation_dispatch()