import pytest
from nhi.risk.rules.trust_policy import analyze_trust_policy


def test_permissive_trust_policy_wildcard_string():
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sts:AssumeRole",
            }
        ],
    }

    findings = analyze_trust_policy(trust_policy, "test-role-permissive")
    assert len(findings) == 1
    assert findings[0]["RuleID"] == "IAM_10"
    assert findings[0]["Severity"] == "CRITICAL"
    assert findings[0]["IdentityName"] == "test-role-permissive"


def test_permissive_trust_policy_aws_dict_wildcard():
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "sts:AssumeRole",
            }
        ],
    }

    findings = analyze_trust_policy(trust_policy, "test-role-permissive-dict")
    assert len(findings) == 1
    assert findings[0]["RuleID"] == "IAM_10"


def test_permissive_trust_policy_aws_list_wildcard():
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": ["arn:aws:iam::123456789012:root", "*"]},
                "Action": ["sts:AssumeRole"],
            }
        ],
    }

    findings = analyze_trust_policy(trust_policy, "test-role-permissive-list")
    assert len(findings) == 1
    assert findings[0]["RuleID"] == "IAM_10"


def test_safe_trust_policy_specific_account():
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }

    findings = analyze_trust_policy(trust_policy, "test-role-safe")
    assert len(findings) == 0


def test_safe_trust_policy_service_principal():
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }

    findings = analyze_trust_policy(trust_policy, "test-role-ec2")
    assert len(findings) == 0


def test_empty_or_malformed_trust_policy():
    assert analyze_trust_policy({}, "test-role-empty") == []
    assert analyze_trust_policy(None, "test-role-none") == []
    assert analyze_trust_policy({"Statement": []}, "test-role-no-stmt") == []