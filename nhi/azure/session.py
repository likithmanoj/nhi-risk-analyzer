from azure.identity import DefaultAzureCredential
import logging, os
logger = logging.getLogger(__name__)

_cached_credentials = None

def get_credentials()-> DefaultAzureCredential:
    global _cached_credentials
    if _cached_credentials is not None:
        return _cached_credentials
    _cached_credentials = DefaultAzureCredential()
    return _cached_credentials
def get_token(scope: str)->str | None:
    try:
        credentials = get_credentials()
        token_obj = credentials.get_token(scope)
        return token_obj.token
    except Exception as e:
        logger.error(f"Failed to acquire Azure token for {scope}: {e}")
        
def get_subscription_id() -> str:
    sub_id = os.environ.get("AZURE_SUBSCRIPTION_ID")
    if not sub_id:
        raise ValueError("AZURE_SUBSCRIPTION_ID environment variable is not set.")
    return sub_id

    


