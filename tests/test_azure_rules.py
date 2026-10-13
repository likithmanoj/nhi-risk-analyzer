import unittest
from nhi.risk.rules.azure.privilege_escalation import (
    analyze_subscription_owner_contributor,
    analyze_graph_app_role_assignment,
    analyze_vm_contributor_run_command,
    analyze_key_vault_secret_officer,
)


class TestAzureSubscriptionOwnerRule(unittest.TestCase):
    def test_positive_subscription_owner_nested(self):
        assignments = [
            {
                "id": "/subscriptions/sub-123/providers/Microsoft.Authorization/roleAssignments/ra-1",
                "properties": {
                    "roleDefinitionName": "Owner",
                    "principalId": "sp-uuid-001",
                    "principalType": "ServicePrincipal",
                    "scope": "/subscriptions/sub-123",
                },
            }
        ]
        findings = analyze_subscription_owner_contributor(assignments)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["RuleID"], "AZURE_01")
        self.assertEqual(findings[0]["Severity"], "CRITICAL")
        self.assertEqual(findings[0]["IdentityName"], "sp-uuid-001")
        self.assertEqual(findings[0]["Role"], "Owner")

    def test_positive_subscription_user_access_admin_flat(self):
        assignments = [
            {
                "roleDefinitionName": "User Access Administrator",
                "principalId": "sp-uuid-002",
                "principalType": "ServicePrincipal",
                "scope": "/subscriptions/sub-456",
            }
        ]
        findings = analyze_subscription_owner_contributor(assignments)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["RuleID"], "AZURE_01")
        self.assertEqual(findings[0]["Role"], "User Access Administrator")

    def test_ignores_human_users_and_groups(self):
        assignments = [
            {
                "roleDefinitionName": "Owner",
                "principalId": "user-uuid-1",
                "principalType": "User",
                "scope": "/subscriptions/sub-123",
            },
            {
                "roleDefinitionName": "Owner",
                "principalId": "group-uuid-1",
                "principalType": "Group",
                "scope": "/subscriptions/sub-123",
            },
        ]
        findings = analyze_subscription_owner_contributor(assignments)
        self.assertEqual(findings, [])

    def test_ignores_resource_group_scoped_assignments(self):
        assignments = [
            {
                "roleDefinitionName": "Owner",
                "principalId": "sp-uuid-003",
                "principalType": "ServicePrincipal",
                "scope": "/subscriptions/sub-123/resourceGroups/rg-dev",
            }
        ]
        findings = analyze_subscription_owner_contributor(assignments)
        self.assertEqual(findings, [])

    def test_defensive_edge_cases(self):
        self.assertEqual(analyze_subscription_owner_contributor(None), [])
        self.assertEqual(analyze_subscription_owner_contributor({}), [])
        self.assertEqual(
            analyze_subscription_owner_contributor([{"properties": {"scope": None}}]),
            [],
        )


class TestAzureGraphAppRoleRule(unittest.TestCase):
    def test_positive_app_role_assignment(self):
        sps = [
            {
                "appId": "sp-graph-001",
                "displayName": "Deployment-Pipeline-SP",
                "apiPermissions": ["AppRoleAssignment.ReadWrite.All", "User.Read"],
            }
        ]
        findings = analyze_graph_app_role_assignment(sps)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["RuleID"], "AZURE_02")
        self.assertEqual(findings[0]["Severity"], "CRITICAL")
        self.assertEqual(findings[0]["Role"], "AppRoleAssignment.ReadWrite.All")

    def test_ignores_safe_permissions(self):
        sps = [
            {
                "appId": "sp-reader-001",
                "displayName": "Audit-SP",
                "apiPermissions": ["User.Read", "Directory.Read.All"],
            }
        ]
        findings = analyze_graph_app_role_assignment(sps)
        self.assertEqual(findings, [])


class TestAzureVMContributorRule(unittest.TestCase):
    def test_positive_vm_contributor(self):
        assignments = [
            {
                "roleDefinitionName": "Virtual Machine Contributor",
                "principalId": "sp-vm-runner",
                "principalType": "ServicePrincipal",
                "scope": "/subscriptions/sub-123",
            }
        ]
        findings = analyze_vm_contributor_run_command(assignments)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["RuleID"], "AZURE_03")
        self.assertEqual(findings[0]["Severity"], "HIGH")
        self.assertEqual(findings[0]["Role"], "Virtual Machine Contributor")


class TestAzureKeyVaultOfficerRule(unittest.TestCase):
    def test_positive_key_vault_administrator(self):
        assignments = [
            {
                "roleDefinitionName": "Key Vault Administrator",
                "principalId": "sp-kv-admin",
                "principalType": "ServicePrincipal",
                "scope": "/subscriptions/sub-123/resourceGroups/rg-vaults",
            }
        ]
        findings = analyze_key_vault_secret_officer(assignments)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["RuleID"], "AZURE_04")
        self.assertEqual(findings[0]["Severity"], "HIGH")


if __name__ == "__main__":
    unittest.main()
