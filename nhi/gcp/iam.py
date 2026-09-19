import requests
from nhi.gcp.session import get_token, get_project_id
import logging, time

logger = logging.getLogger(__name__)

IAM_BASE_URL = "https://iam.googleapis.com/v1"
CRM_BASE_URL = "https://cloudresourcemanager.googleapis.com/v1"

def fetch_all(url: str, headers: dict | None, key: str = "accounts") -> list:
    max_retries = 5
    if not headers:
        raise ValueError(f"No authorization headers available for {url}")
    results = []
    params = {}
    retries = 0

    while True:
        try:
            response = requests.get(url, headers=headers, params=params, timeout=30)
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
            logger.error(f"GCP API error {response.status_code} for {url}: {response.text}")
            break

        data = response.json()
        results.extend(data.get(key, []))

        next_token = data.get("nextPageToken")
        if not next_token:
            break
        params["pageToken"] = next_token

    return results

def get_gcp_headers() -> dict | None:
    token = get_token()
    if not token:
        return None
    return {"Authorization": f"Bearer {token}"}

def list_service_accounts(project_id: str | None = None) -> list:
    proj_id = project_id or get_project_id()
    url = f"{IAM_BASE_URL}/projects/{proj_id}/serviceAccounts"
    return fetch_all(url, get_gcp_headers(), key="accounts")

def list_service_account_keys(service_account_email: str, project_id: str | None = None) -> list:
    proj_id = project_id or get_project_id()
    url = f"{IAM_BASE_URL}/projects/{proj_id}/serviceAccounts/{service_account_email}/keys"
    return fetch_all(url, get_gcp_headers(), key="keys")

def get_project_iam_policy(project_id: str | None = None) -> dict:
    headers = get_gcp_headers()
    if not headers:
        raise ValueError("No authorization headers available for get_project_iam_policy")
    proj_id = project_id or get_project_id()
    url = f"{CRM_BASE_URL}/projects/{proj_id}:getIamPolicy"
    try:
        response = requests.post(url, headers=headers, timeout=30)
        if response.status_code != 200:
            logger.error(f"GCP API error {response.status_code} for {url}: {response.text}")
            return {}
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Error fetching project IAM policy for {proj_id}: {e}")
        return {}

def list_roles(project_id: str | None = None) -> list:
    proj_id = project_id or get_project_id()
    url = f"{IAM_BASE_URL}/projects/{proj_id}/roles"
    return fetch_all(url, get_gcp_headers(), key="roles")


