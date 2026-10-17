from unittest.mock import patch
from nhi.risk.risk import analyze_inventory
from nhi.risk.runners.azure import run_azure_checks
from nhi.risk.runners.gcp import run_gcp_checks
from nhi.risk.runners.aws import run_aws_checks


def test_analyze_inventory_multi_cloud_aggregation():
    mock_inventory = {
        "metadata": {
            "scanned_providers": ["aws", "azure", "gcp"],
            "failed_providers": [],
        },
        "aws": {
            "users": [
                {
                    "UserName": "test-admin",
                    "AttachedPolicies": [
                        {
                            "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                            "PolicyName": "AdministratorAccess",
                            "PolicyDocument": {
                                "Statement": [
                                    {"Effect": "Allow", "Action": "*", "Resource": "*"}
                                ]
                            },
                        }
                    ],
                    "InlinePolicies": [],
                    "AccessKeys": [],
                }
            ],
            "groups": [],
            "roles": [],
        },
        "azure": {
            "role_assignments": [
                {
                    "properties": {
                        "principalId": "sp-sub-owner",
                        "principalType": "ServicePrincipal",
                        "roleDefinitionName": "Owner",
                        "scope": "/subscriptions/sub-12345",
                    }
                }
            ],
            "service_principals": [],
        },
        "gcp": {
            "iam_policy": {
                "bindings": [
                    {
                        "role": "roles/iam.serviceAccountTokenCreator",
                        "members": ["serviceAccount:sa-attacker@proj.iam.gserviceaccount.com"],
                    }
                ]
            },
            "service_accounts": [],
        },
    }

    with patch("nhi.risk.risk.create_inventory", return_value=mock_inventory):
        findings = analyze_inventory()

    rule_ids = {f.get("RuleID") for f in findings}
    assert "AWS_01" in rule_ids or "AWS_03" in rule_ids
    assert "AZURE_01" in rule_ids
    assert "GCP_01" in rule_ids


def test_analyze_inventory_selective_clouds():
    mock_inventory_aws_only = {
        "metadata": {
            "scanned_providers": ["aws"],
            "failed_providers": [],
        },
        "aws": {
            "users": [
                {
                    "UserName": "test-admin",
                    "AttachedPolicies": [
                        {
                            "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                            "PolicyName": "AdministratorAccess",
                            "PolicyDocument": {
                                "Statement": [
                                    {"Effect": "Allow", "Action": "*", "Resource": "*"}
                                ]
                            },
                        }
                    ],
                    "InlinePolicies": [],
                    "AccessKeys": [],
                }
            ],
            "groups": [],
            "roles": [],
        },
    }

    with patch("nhi.risk.risk.create_inventory", return_value=mock_inventory_aws_only) as mock_create:
        findings = analyze_inventory(clouds=["aws"])
        mock_create.assert_called_once_with(clouds=["aws"])

    rule_ids = {f.get("RuleID") for f in findings}
    assert any(r.startswith("AWS_") for r in rule_ids)
    assert not any(r.startswith("AZURE_") for r in rule_ids)
    assert not any(r.startswith("GCP_") for r in rule_ids)


def test_analyze_inventory_legacy_flat_dict_fallback():
    mock_legacy_inventory = {
        "users": [
            {
                "UserName": "legacy-admin",
                "AttachedPolicies": [
                    {
                        "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                        "PolicyName": "AdministratorAccess",
                        "PolicyDocument": {
                            "Statement": [
                                {"Effect": "Allow", "Action": "*", "Resource": "*"}
                            ]
                        },
                    }
                ],
                "InlinePolicies": [],
                "AccessKeys": [],
            }
        ],
        "groups": [],
        "roles": [],
    }

    with patch("nhi.risk.risk.create_inventory", return_value=mock_legacy_inventory):
        findings = analyze_inventory()

    assert len(findings) > 0
    rule_ids = {f.get("RuleID") for f in findings}
    assert any(r.startswith("AWS_") for r in rule_ids)


def test_run_azure_checks_all_rules():
    azure_data = {
        "role_assignments": [
            {
                "properties": {
                    "principalId": "sp-owner",
                    "principalType": "ServicePrincipal",
                    "roleDefinitionName": "Owner",
                    "scope": "/subscriptions/sub-123",
                }
            },
            {
                "properties": {
                    "principalId": "sp-vm",
                    "principalType": "ServicePrincipal",
                    "roleDefinitionName": "Virtual Machine Contributor",
                }
            },
            {
                "properties": {
                    "principalId": "sp-kv",
                    "principalType": "ServicePrincipal",
                    "roleDefinitionName": "Key Vault Secrets Officer",
                }
            },
        ],
        "service_principals": [
            {
                "displayName": "sp-graph",
                "appRoleAssignments": ["AppRoleAssignment.ReadWrite.All"],
            },
            {
                "displayName": "sp-stale",
                "keyCredentials": [{"keyId": "k-never-expires"}],
            },
        ],
    }

    findings = run_azure_checks(azure_data)
    rule_ids = {f.get("RuleID") for f in findings}

    assert "AZURE_01" in rule_ids
    assert "AZURE_02" in rule_ids
    assert "AZURE_03" in rule_ids
    assert "AZURE_04" in rule_ids
    assert "AZURE_05" in rule_ids


def test_run_gcp_checks_all_rules():
    gcp_data = {
        "iam_policy": {
            "bindings": [
                {
                    "role": "roles/iam.serviceAccountTokenCreator",
                    "members": ["serviceAccount:sa-token@proj.iam.gserviceaccount.com"],
                },
                {
                    "role": "roles/iam.serviceAccountKeyAdmin",
                    "members": ["serviceAccount:sa-key@proj.iam.gserviceaccount.com"],
                },
                {
                    "role": "roles/iam.serviceAccountUser",
                    "members": ["serviceAccount:sa-user@proj.iam.gserviceaccount.com"],
                },
                {
                    "role": "roles/iam.securityAdmin",
                    "members": ["serviceAccount:sa-sec@proj.iam.gserviceaccount.com"],
                },
                {
                    "role": "roles/cloudfunctions.developer",
                    "members": ["serviceAccount:sa-deploy@proj.iam.gserviceaccount.com"],
                },
            ]
        },
        "service_accounts": [
            {
                "email": "sa-stale@proj.iam.gserviceaccount.com",
                "keys": [
                    {
                        "name": "projects/proj/serviceAccounts/sa-stale/keys/k1",
                        "keyType": "USER_MANAGED",
                        "validAfterTime": "2020-01-01T00:00:00Z",
                    }
                ],
            }
        ],
    }

    findings = run_gcp_checks(gcp_data)
    rule_ids = {f.get("RuleID") for f in findings}

    assert "GCP_01" in rule_ids
    assert "GCP_02" in rule_ids
    assert "GCP_03" in rule_ids
    assert "GCP_04" in rule_ids
    assert "GCP_05" in rule_ids
    assert "GCP_06" in rule_ids
