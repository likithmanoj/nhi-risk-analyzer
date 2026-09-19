import google.auth
from google.auth.transport.requests import Request
import logging, os
logger = logging.getLogger(__name__)

_cached_credentials = None
_cached_project_id = None

def get_credentials():
    global _cached_credentials, _cached_project_id
    if _cached_credentials is not None:
        return _cached_credentials
    credentials, project_id = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    _cached_credentials = credentials
    _cached_project_id = project_id
    return _cached_credentials

def get_token()-> str | None:
    try:
        credentials = get_credentials()
        if not credentials.valid:
            credentials.refresh(Request())
        return credentials.token
    except Exception as e:
        logger.error(f"Failed to acquire GCP token: {e}")
        
def get_project_id() -> str:
    proj_id = os.environ.get("GCP_PROJECT_ID")
    if proj_id:
        return proj_id
    get_credentials()
    if _cached_project_id:
        return _cached_project_id        
    raise ValueError("GCP_PROJECT_ID environment variable is not set and could not be detected from credentials.")
