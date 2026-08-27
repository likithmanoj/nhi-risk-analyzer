import pytest
from nhi.remediation.policy_surgery import (
    is_non_resource_action,
    partition_actions,
    split_policy_statement,
)


def test_is_non_resource_action():
    assert is_non_resource_action("iam:ListUsers") is True
    assert is_non_resource_action("ec2:DescribeInstances") is True
    assert is_non_resource_action("sts:GetCallerIdentity") is True
    assert is_non_resource_action("s3:PutObject") is False
    assert is_non_resource_action("iam:CreateUser") is False
    assert is_non_resource_action("s3:*") is False
    assert is_non_resource_action("*") is False


def test_partition_actions():
    actions = ["iam:ListUsers", "s3:PutObject", "ec2:DescribeInstances"]
    discovery, scoped = partition_actions(actions)

    assert discovery == ["iam:ListUsers", "ec2:DescribeInstances"]
    assert scoped == ["s3:PutObject"]


def test_split_mixed_statement():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "MixedAccess",
                "Effect": "Allow",
                "Action": ["iam:ListUsers", "s3:PutObject"],
                "Resource": "*",
            }
        ],
    }
    placeholder = "arn:aws:s3:::target-bucket/*"
    result = split_policy_statement(policy, target_arn_placeholder=placeholder)

    statements = result["Statement"]
    assert len(statements) == 2

    discovery_stmt = statements[0]
    assert discovery_stmt["Sid"] == "MixedAccessDiscovery"
    assert discovery_stmt["Effect"] == "Allow"
    assert discovery_stmt["Action"] == ["iam:ListUsers"]
    assert discovery_stmt["Resource"] == "*"

    scoped_stmt = statements[1]
    assert scoped_stmt["Sid"] == "MixedAccessScoped"
    assert scoped_stmt["Effect"] == "Allow"
    assert scoped_stmt["Action"] == ["s3:PutObject"]
    assert scoped_stmt["Resource"] == placeholder


def test_pure_discovery_statement_remains_unchanged():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DiscoveryOnly",
                "Effect": "Allow",
                "Action": ["iam:ListUsers", "ec2:DescribeInstances"],
                "Resource": "*",
            }
        ],
    }
    result = split_policy_statement(policy)

    assert len(result["Statement"]) == 1
    assert result["Statement"][0] == policy["Statement"][0]


def test_pure_scoped_with_wildcard_resource_rewritten():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "OverprivilegedWrite",
                "Effect": "Allow",
                "Action": ["s3:PutObject", "dynamodb:PutItem"],
                "Resource": "*",
            }
        ],
    }
    placeholder = "arn:aws:*:*:*:placeholder/*"
    result = split_policy_statement(policy, target_arn_placeholder=placeholder)

    assert len(result["Statement"]) == 1
    stmt = result["Statement"][0]
    assert stmt["Sid"] == "OverprivilegedWrite"
    assert stmt["Action"] == ["s3:PutObject", "dynamodb:PutItem"]
    assert stmt["Resource"] == placeholder


def test_already_scoped_statement_passes_through():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ProperlyScoped",
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": "arn:aws:s3:::my-bucket/*",
            }
        ],
    }
    result = split_policy_statement(policy)

    assert len(result["Statement"]) == 1
    assert result["Statement"][0] == policy["Statement"][0]


def test_deny_statement_passes_through():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyRoot",
                "Effect": "Deny",
                "Action": ["*"],
                "Resource": "*",
            }
        ],
    }
    result = split_policy_statement(policy)

    assert len(result["Statement"]) == 1
    assert result["Statement"][0]["Effect"] == "Deny"
    assert result["Statement"][0]["Resource"] == "*"


def test_condition_block_preserved_on_split():
    condition = {"StringEquals": {"aws:PrincipalOrgID": "o-1234567890"}}
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "OrgRestrictedMixed",
                "Effect": "Allow",
                "Action": ["iam:ListRoles", "s3:GetObject"],
                "Resource": "*",
                "Condition": condition,
            }
        ],
    }
    result = split_policy_statement(policy)

    assert len(result["Statement"]) == 2
    assert result["Statement"][0]["Condition"] == condition
    assert result["Statement"][1]["Condition"] == condition


def test_metadata_preservation_and_immutability():
    original_policy = {
        "Version": "2012-10-17",
        "Id": "PolicyCustomMetadata123",
        "CustomTag": "SecurityAutomation",
        "Statement": [
            {
                "Sid": "Mixed",
                "Effect": "Allow",
                "Action": ["iam:ListUsers", "s3:PutObject"],
                "Resource": "*",
            }
        ],
    }

    result = split_policy_statement(original_policy)

    assert result["Version"] == "2012-10-17"
    assert result["Id"] == "PolicyCustomMetadata123"
    assert result["CustomTag"] == "SecurityAutomation"

    assert len(original_policy["Statement"]) == 1
    assert len(result["Statement"]) == 2