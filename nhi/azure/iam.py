import requests
from nhi.azure.session import get_token, get_subscription_id

GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
ARM_BASE_URL = "https://management.azure.com"

API_VERSION_ROLE_ASSIGNMENTS = "2022-04-01"
API_VERSION_ROLE_DEFINITIONS = "2022-04-01"
API_VERSION_USER_ASSIGNED_IDENTITIES = "2024-11-30"

def get_graph_headers() -> dict | None:
    token = get_token("https://graph.microsoft.com/.default")
    if not token:
        return None
    return {"Authorization": f"Bearer {token}"}

def list_users() -> list:
    headers = get_graph_headers()
    if not headers:
        return []
    url = f"{GRAPH_BASE_URL}/users"
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return []
    return response.json().get("value", [])

def list_groups() -> list:
    headers = get_graph_headers()
    if not headers:
        return []
    url = f"{GRAPH_BASE_URL}/groups"
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return []
    return response.json().get("value", [])

def list_group_members(group_id: str) -> list:
    headers = get_graph_headers()
    if not headers:
        return []
    url = f"{GRAPH_BASE_URL}/groups/{group_id}/members"
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return []
    return response.json().get("value", [])

def list_service_principals() -> list:
    headers = get_graph_headers()
    if not headers:
        return []
    url = f"{GRAPH_BASE_URL}/servicePrincipals"
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return []
    return response.json().get("value", [])

def list_applications() -> list:
    headers = get_graph_headers()
    if not headers:
        return []
    url = f"{GRAPH_BASE_URL}/applications"
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return []
    return response.json().get("value", [])

def get_arm_headers() -> dict | None:
    token = get_token("https://management.azure.com/.default")
    if not token:
        return None
    return {"Authorization": f"Bearer {token}"}

def list_role_assignments() -> list:
    headers = get_arm_headers()
    if not headers:
        return []
    subscription_id = get_subscription_id()
    url = f"{ARM_BASE_URL}/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleAssignments?api-version={API_VERSION_ROLE_ASSIGNMENTS}"
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return []
    return response.json().get("value", [])

def list_role_definitions() -> list:
    headers = get_arm_headers()
    if not headers:
        return []
    subscription_id = get_subscription_id()
    url = f"{ARM_BASE_URL}/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions?api-version={API_VERSION_ROLE_DEFINITIONS}"
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return []
    return response.json().get("value", [])

def get_role_definition(role_definition_id: str) -> dict:
    headers = get_arm_headers()
    if not headers:
        return {}
    subscription_id = get_subscription_id()
    url = f"{ARM_BASE_URL}/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions/{role_definition_id}?api-version={API_VERSION_ROLE_DEFINITIONS}"
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return {}
    return response.json()

def list_user_assigned_identities() -> list:
    headers = get_arm_headers()
    if not headers:
        return []
    subscription_id = get_subscription_id()
    url = f"{ARM_BASE_URL}/subscriptions/{subscription_id}/providers/Microsoft.ManagedIdentity/userAssignedIdentities?api-version={API_VERSION_USER_ASSIGNED_IDENTITIES}"
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return []
    return response.json().get("value", [])

