from azure.identity import DefaultAzureCredential
from azure.core.exceptions import ClientAuthenticationError
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
    except ClientAuthenticationError as e:
        logger.warning(f"ClientAuthenticationError raised on Azure")
def get_subscription_id() -> str:
    return os.environ.get("AZURE_SUBSCRIPTION_ID", "00000000-0000-0000-0000-000000000000")


