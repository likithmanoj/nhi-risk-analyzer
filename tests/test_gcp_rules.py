import unittest
from nhi.risk.rules.gcp.privilege_escalation import (
    analyze_service_account_token_creator,
    analyze_service_account_key_admin,
    analyze_service_account_user,
    analyze_iam_security_admin,
    analyze_deployment_privesc,
)
from nhi.risk.rules.gcp.credentials import analyze_stale_service_account_keys


class TestGCPAccessTokenCreatorRule(unittest.TestCase):
    def test_positive_service_account_token_creator(self):
        policy = {
            "bindings": [
                {
                    "role": "roles/iam.serviceAccountTokenCreator",
                    "members": [
                        "serviceAccount:workload-sa@my-project.iam.gserviceaccount.com"
                    ],
                }
            ]
        }
        findings = analyze_service_account_token_creator(policy)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["RuleID"], "GCP_01")
        self.assertEqual(finding["Severity"], "CRITICAL")
        self.assertEqual(finding["IdentityType"], "ServiceAccount")
        self.assertEqual(
            finding["IdentityName"],
            "workload-sa@my-project.iam.gserviceaccount.com",
        )
        self.assertEqual(finding["Role"], "roles/iam.serviceAccountTokenCreator")

    def test_ignores_human_users_and_groups(self):
        policy = {
            "bindings": [
                {
                    "role": "roles/iam.serviceAccountTokenCreator",
                    "members": [
                        "user:admin@company.com",
                        "group:security-team@company.com",
                    ],
                }
            ]
        }
        findings = analyze_service_account_token_creator(policy)
        self.assertEqual(findings, [])

    def test_unrelated_role_produces_no_findings(self):
        policy = {
            "bindings": [
                {
                    "role": "roles/viewer",
                    "members": [
                        "serviceAccount:reader-sa@my-project.iam.gserviceaccount.com"
                    ],
                }
            ]
        }
        findings = analyze_service_account_token_creator(policy)
        self.assertEqual(findings, [])

    def test_multiple_service_accounts_in_binding(self):
        policy = {
            "bindings": [
                {
                    "role": "roles/iam.serviceAccountTokenCreator",
                    "members": [
                        "serviceAccount:sa-one@my-project.iam.gserviceaccount.com",
                        "user:alice@company.com",
                        "serviceAccount:sa-two@my-project.iam.gserviceaccount.com",
                    ],
                }
            ]
        }
        findings = analyze_service_account_token_creator(policy)
        self.assertEqual(len(findings), 2)
        sa_names = [f["IdentityName"] for f in findings]
        self.assertIn("sa-one@my-project.iam.gserviceaccount.com", sa_names)
        self.assertIn("sa-two@my-project.iam.gserviceaccount.com", sa_names)

    def test_defensive_edge_cases(self):
        self.assertEqual(analyze_service_account_token_creator(None), [])
        self.assertEqual(analyze_service_account_token_creator({}), [])
        self.assertEqual(analyze_service_account_token_creator({"bindings": None}), [])
        self.assertEqual(analyze_service_account_token_creator({"bindings": "invalid"}), [])
        self.assertEqual(
            analyze_service_account_token_creator(
                {"bindings": [{"role": "roles/iam.serviceAccountTokenCreator", "members": None}]}
            ),
            [],
        )
        self.assertEqual(
            analyze_service_account_token_creator(
                {"bindings": [None, 123, "string-binding"]}
            ),
            [],
        )



class TestGCPKeyAdminRule(unittest.TestCase):
    def test_positive_service_account_key_admin(self):
        policy = {
            "bindings": [
                {
                    "role": "roles/iam.serviceAccountKeyAdmin",
                    "members": ["serviceAccount:key-admin-sa@project.iam.gserviceaccount.com"],
                }
            ]
        }
        findings = analyze_service_account_key_admin(policy)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["RuleID"], "GCP_02")
        self.assertEqual(findings[0]["Severity"], "CRITICAL")
        self.assertEqual(findings[0]["IdentityName"], "key-admin-sa@project.iam.gserviceaccount.com")


class TestGCPServiceAccountUserRule(unittest.TestCase):
    def test_positive_service_account_user(self):
        policy = {
            "bindings": [
                {
                    "role": "roles/iam.serviceAccountUser",
                    "members": ["serviceAccount:runner-sa@project.iam.gserviceaccount.com"],
                }
            ]
        }
        findings = analyze_service_account_user(policy)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["RuleID"], "GCP_03")
        self.assertEqual(findings[0]["Severity"], "HIGH")


class TestGCPIamSecurityAdminRule(unittest.TestCase):
    def test_positive_security_admin(self):
        policy = {
            "bindings": [
                {
                    "role": "roles/iam.securityAdmin",
                    "members": ["serviceAccount:admin-sa@project.iam.gserviceaccount.com"],
                }
            ]
        }
        findings = analyze_iam_security_admin(policy)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["RuleID"], "GCP_04")
        self.assertEqual(findings[0]["Severity"], "CRITICAL")


class TestGCPDeploymentPrivescRule(unittest.TestCase):
    def test_positive_cloudfunctions_developer(self):
        policy = {
            "bindings": [
                {
                    "role": "roles/cloudfunctions.developer",
                    "members": ["serviceAccount:deployer-sa@project.iam.gserviceaccount.com"],
                }
            ]
        }
        findings = analyze_deployment_privesc(policy)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["RuleID"], "GCP_05")
        self.assertEqual(findings[0]["Severity"], "HIGH")
        self.assertEqual(findings[0]["IdentityName"], "deployer-sa@project.iam.gserviceaccount.com")

    def test_positive_run_developer(self):
        policy = {
            "bindings": [
                {
                    "role": "roles/run.developer",
                    "members": ["serviceAccount:run-deployer@project.iam.gserviceaccount.com"],
                }
            ]
        }
        findings = analyze_deployment_privesc(policy)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["RuleID"], "GCP_05")


class TestGCPStaleKeysRule(unittest.TestCase):
    def test_positive_stale_user_managed_key(self):
        sas = [
            {
                "email": "app-sa@project.iam.gserviceaccount.com",
                "keys": [
                    {
                        "name": "projects/p/serviceAccounts/s/keys/key-123",
                        "keyType": "USER_MANAGED",
                        "validAfterTime": "2020-01-01T00:00:00Z",
                    }
                ],
            }
        ]
        findings = analyze_stale_service_account_keys(sas)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["RuleID"], "GCP_06")
        self.assertEqual(findings[0]["Severity"], "MEDIUM")
        self.assertEqual(findings[0]["IdentityName"], "app-sa@project.iam.gserviceaccount.com")
        self.assertEqual(findings[0]["TargetID"], "key-123")

    def test_ignores_system_managed_keys(self):
        sas = [
            {
                "email": "app-sa@project.iam.gserviceaccount.com",
                "keys": [
                    {
                        "name": "projects/p/serviceAccounts/s/keys/system-key",
                        "keyType": "SYSTEM_MANAGED",
                        "validAfterTime": "2020-01-01T00:00:00Z",
                    }
                ],
            }
        ]
        findings = analyze_stale_service_account_keys(sas)
        self.assertEqual(findings, [])

    def test_ignores_recently_created_keys(self):
        from datetime import datetime, timezone
        now_iso = datetime.now(timezone.utc).isoformat()
        sas = [
            {
                "email": "fresh-sa@project.iam.gserviceaccount.com",
                "keys": [
                    {
                        "name": "projects/p/serviceAccounts/s/keys/fresh-key",
                        "keyType": "USER_MANAGED",
                        "validAfterTime": now_iso,
                    }
                ],
            }
        ]
        findings = analyze_stale_service_account_keys(sas)
        self.assertEqual(findings, [])

    def test_defensive_edge_cases(self):
        self.assertEqual(analyze_stale_service_account_keys(None), [])
        self.assertEqual(analyze_stale_service_account_keys({}), [])
        self.assertEqual(analyze_stale_service_account_keys([{"keys": None}]), [])


if __name__ == "__main__":
    unittest.main()
