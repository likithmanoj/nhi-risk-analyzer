import pytest
from nhi.risk.rules.data_perimeter import (
    analyze_policy_for_s3_exfiltration,
    analyze_policy_for_kms_decryption,
)


@pytest.mark.parametrize("action", ["s3:GetObject", "s3:GetObjectVersion", "s3:*"])
def test_s3_exfiltration_unconstrained_resource(action):
    policy = [{
        "PolicyName": "S3ReadPolicy",
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
    findings = analyze_policy_for_s3_exfiltration(policy, "Role", "TestRole")
    assert len(findings) == 1
    assert findings[0]["RuleID"] == "IAM_14"
    assert findings[0]["Severity"] == "HIGH"


def test_s3_exfiltration_safe_actions_pass():
    policy = [{
        "PolicyName": "S3WriteOnlyPolicy",
        "PolicyDocument": {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:PutObject"],
                    "Resource": "*",
                }
            ]
        },
    }]
    findings = analyze_policy_for_s3_exfiltration(policy, "Role", "TestRole")
    assert len(findings) == 0


@pytest.mark.parametrize("action", ["kms:Decrypt", "kms:ReEncrypt*", "kms:*"])
def test_kms_decryption_unconstrained_resource(action):
    policy = [{
        "PolicyName": "KMSDecryptPolicy",
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
    findings = analyze_policy_for_kms_decryption(policy, "Role", "TestRole")
    assert len(findings) == 1
    assert findings[0]["RuleID"] == "IAM_16"
    assert findings[0]["Severity"] == "HIGH"


def test_kms_decryption_safe_encrypt_pass():
    policy = [{
        "PolicyName": "KMSEncryptOnlyPolicy",
        "PolicyDocument": {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["kms:Encrypt", "kms:GenerateDataKey"],
                    "Resource": "*",
                }
            ]
        },
    }]
    findings = analyze_policy_for_kms_decryption(policy, "Role", "TestRole")
    assert len(findings) == 0