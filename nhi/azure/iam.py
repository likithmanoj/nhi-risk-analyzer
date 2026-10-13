import requests
from nhi.azure.session import get_token, get_subscription_id
import logging, time

logger = logging.getLogger(__name__)

GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
ARM_BASE_URL = "https://management.azure.com"

API_VERSION_ROLE_ASSIGNMENTS = "2022-04-01"
API_VERSION_ROLE_DEFINITIONS = "2022-04-01"
API_VERSION_USER_ASSIGNED_IDENTITIES = "2024-11-30"

def fetch_all(url: str, headers: dict | None) -> list:
    max_retries = 5
    if not headers:
        raise ValueError(f"No authorization headers available for {url}")
    results = []
    retries = 0
      
    while url:
        try:
            response = requests.get(url, headers=headers, timeout = 30)
        except requests.RequestException as e:
            logger.error(f"Network error while requesting {url}: {e}")
            break
        if response.status_code == 429:
            if retries >= max_retries:
                logger.error(f"Rate limit retry limit ({max_retries}) exceeded for {url}")
                break
            retries += 1
            retry_after = int(response.headers.get("Retry-After", 2))
            logger.warning(f"Rate limited (429) on {url}. Retrying after {retry_after}s...")
            time.sleep(retry_after)
            continue
        retries = 0
        if response.status_code != 200:
            logger.error(f"Azure API error {response.status_code} for {url}: {response.text}")
            break
        data = response.json()
        results.extend(data.get("value", []))
        url = data.get("@odata.nextLink") or data.get("nextLink")
    return results

def get_graph_headers() -> dict | None:
    token = get_token("https://graph.microsoft.com/.default")
    if not token:
        return None
    return {"Authorization": f"Bearer {token}"}

def get_arm_headers() -> dict | None:
    token = get_token("https://management.azure.com/.default")
    if not token:
        return None
    return {"Authorization": f"Bearer {token}"}

def list_users()-> list:
    return fetch_all(f"{GRAPH_BASE_URL}/users", get_graph_headers())

def list_groups() -> list:
    return fetch_all(f"{GRAPH_BASE_URL}/groups", get_graph_headers())

def list_group_members(group_id: str) -> list:
    return fetch_all(f"{GRAPH_BASE_URL}/groups/{group_id}/members", get_graph_headers())    

def list_service_principals() -> list:
    return fetch_all(f"{GRAPH_BASE_URL}/servicePrincipals", get_graph_headers())

def list_applications() -> list:
   return fetch_all(f"{GRAPH_BASE_URL}/applications", get_graph_headers())   

def list_role_assignments() -> list:
    subscription_id = get_subscription_id()
    url = f"{ARM_BASE_URL}/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleAssignments?api-version={API_VERSION_ROLE_ASSIGNMENTS}"
    return fetch_all(url, get_arm_headers())

def list_role_definitions() -> list:
    subscription_id = get_subscription_id()
    url = f"{ARM_BASE_URL}/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions?api-version={API_VERSION_ROLE_DEFINITIONS}"
    return fetch_all(url, get_arm_headers())

def list_user_assigned_identities() -> list:
    subscription_id = get_subscription_id()
    url = f"{ARM_BASE_URL}/subscriptions/{subscription_id}/providers/Microsoft.ManagedIdentity/userAssignedIdentities?api-version={API_VERSION_USER_ASSIGNED_IDENTITIES}"
    return fetch_all(url, get_arm_headers())

def get_role_definition(role_definition_id: str) -> dict:
    headers = get_arm_headers()
    if not headers:
        raise ValueError("No authorization headers available for get_role_definition")
    subscription_id = get_subscription_id()
    url = f"{ARM_BASE_URL}/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions/{role_definition_id}?api-version={API_VERSION_ROLE_DEFINITIONS}"
    try:
        response = requests.get(url, headers=headers, timeout=30)
        return response.json() if response.status_code == 200 else {}
    except requests.RequestException as e:
        logger.error(f"Error fetching role definition {role_definition_id}: {e}")
        return {}

