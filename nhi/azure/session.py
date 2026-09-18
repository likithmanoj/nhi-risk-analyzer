import os
from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient

_cached_auth_client = None

def get_authorization_client():
    global _cached_auth_client
    if _cached_auth_client is not None:
        return _cached_auth_client
    
    subscription_id = os.environ.get("AZURE_SUBSCRIPTION_ID", "dummy-sub-id")
    credential = DefaultAzureCredential()
    _cached_auth_client = AuthorizationManagementClient(credential, subscription_id)
    return _cached_auth_client
