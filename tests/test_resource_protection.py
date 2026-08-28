import pytest
from nhi.risk.rules.resource_protection import analyze_policy_for_defense_evasion


@pytest.mark.parametrize("action", [
    "cloudtrail:StopLogging",
    "cloudtrail:DeleteTrail",
    "guardduty:DeleteDetector",
    "guardduty:DisassociateFromMasterAccount",
    "kms:DisableKey",
    "kms:ScheduleKeyDeletion",
])
def test_defense_evasion_tampering_actions(action):
    policy = [{
        "PolicyName": "DefenseEvasionPolicy",
        "PolicyDocument": {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": action,
                    "Resource": "*",
                }
            ]
        },
    }]
    findings = analyze_policy_for_defense_evasion(policy, "Role", "TestRole")
    assert len(findings) == 1
    assert findings[0]["RuleID"] == "IAM_15"
    assert findings[0]["Severity"] == "CRITICAL"


def test_defense_evasion_benign_actions_pass():
    policy = [{
        "PolicyName": "SafeMonitoringPolicy",
        "PolicyDocument": {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["cloudtrail:DescribeTrails", "guardduty:ListDetectors"],
                    "Resource": "*",
                }
            ]
        },
    }]
    findings = analyze_policy_for_defense_evasion(policy, "Role", "TestRole")
    assert len(findings) == 0