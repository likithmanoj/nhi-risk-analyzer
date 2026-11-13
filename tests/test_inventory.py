import unittest
from unittest.mock import MagicMock, patch

from nhi.services.inventory import create_inventory


class TestInventoryMockInjection(unittest.TestCase):

  @patch('nhi.services.inventory.iam')
  def test_create_inventory_injects_last_used_metadata(self, mock_iam):
    """Injects mock IAM responses to verify key enrichment loop without live AWS calls."""
    # 1. Setup mock returns for IAM module calls
    mock_iam.list_users.return_value = [{'UserName': 'test-user'}]
    mock_iam.list_roles.return_value = []
    mock_iam.list_groups.return_value = []
    mock_iam.list_attached_user_policies.return_value = []
    mock_iam.list_user_inline_policies.return_value = []

    # Mock access keys list returned by list_access_keys
    mock_iam.get_access_keys.return_value = [{
        'AccessKeyId': 'AKIA_MOCK_TEST_KEY',
        'Status': 'Active',
        'CreateDate': '2026-01-01T00:00:00+00:00',
    }]

    # 2. Inject mock return for get_access_key_last_used
    mock_iam.get_access_key_last_used.return_value = {
        'LastUsedDate': '2026-07-01T12:00:00+00:00',
        'ServiceName': 's3',
        'Region': 'us-west-2',
    }

    # 3. Execute inventory generation
    result = create_inventory()

    # 4. Assertions
    user = result['users'][0]
    key = user['AccessKeys'][0]

    # Verify get_access_key_last_used was called with the right key string
    mock_iam.get_access_key_last_used.assert_called_once_with(
        'AKIA_MOCK_TEST_KEY'
    )

    # Verify the metadata was attached to the access key object
    self.assertIn('AccessKeyLastUsed', key)
    self.assertEqual(
        key['AccessKeyLastUsed']['LastUsedDate'], '2026-07-01T12:00:00+00:00'
    )
    self.assertEqual(key['AccessKeyLastUsed']['ServiceName'], 's3')

  @patch('nhi.azure.iam.list_service_principals', return_value=[])
  @patch('nhi.azure.iam.list_applications', return_value=[])
  @patch('nhi.azure.iam.list_user_assigned_identities', return_value=[])
  @patch('nhi.azure.iam.list_role_assignments')
  @patch('nhi.azure.iam.list_role_definitions')
  def test_get_azure_inventory_resolves_role_definition_names_and_permissions(
      self, mock_defs, mock_assigns, mock_uai, mock_apps, mock_sp
  ):
    """Verifies that Azure role assignments with raw GUIDs are enriched with friendly names and permissions."""
    from nhi.services.inventory import get_azure_inventory

    # 1. Real Azure ARM shape: only roleDefinitionId with GUID, NO roleDefinitionName
    mock_assigns.return_value = [{
        'id': '/subscriptions/sub-123/providers/Microsoft.Authorization/roleAssignments/ra-1',
        'properties': {
            'principalId': 'sp-workload-runner',
            'principalType': 'ServicePrincipal',
            'roleDefinitionId': '/Subscriptions/sub-123/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635',
            'scope': '/subscriptions/sub-123',
        },
    }]

    # 2. Azure role definitions catalog
    mock_defs.return_value = [{
        'id': '/subscriptions/sub-123/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635',
        'properties': {
            'roleName': 'Owner',
            'permissions': [{'actions': ['*'], 'notActions': []}],
        },
    }]

    # 3. Execute inventory
    result = get_azure_inventory()

    # 4. Verify resolution
    assignment = result['role_assignments'][0]
    self.assertEqual(assignment['properties']['roleDefinitionName'], 'Owner')
    self.assertEqual(
        assignment['properties']['permissions'],
        [{'actions': ['*'], 'notActions': []}],
    )


if __name__ == '__main__':
  unittest.main()