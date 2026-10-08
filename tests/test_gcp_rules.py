import unittest
from nhi.risk.rules.gcp.privilege_escalation import analyze_service_account_token_creator


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


if __name__ == "__main__":
    unittest.main()
