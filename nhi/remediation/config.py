import yaml
import logging
import sys

logging.basicConfig(
    level=logging.INFO, # Use INFO in production to capture info, warnings, and errors
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stderr),  # Direct errors to standard error stream
        logging.FileHandler("production.log") # Persist logs to a secure file
    ]
)
logger = logging.getLogger(__name__)

def load_ignore_config(config_path = 'nhi-ignore.yaml'):
    default_config = {
    "ignore_users": [],
    "ignore_roles": [],
    "ignore_access_keys": []
    }
    try:
        with open(config_path,"r") as f:
            ignore_data = yaml.safe_load(f)
            data = ignore_data if isinstance(ignore_data, dict) else {}
            exemptions = data.get("exemptions") or {}
            response = {
            "ignore_users" : exemptions.get('users') or [],
            "ignore_roles" : exemptions.get('roles') or [],
            "ignore_access_keys" : exemptions.get('access_keys') or []
            }
            return response
    except yaml.YAMLError:
            logger.error("Check nhi-ignore.yaml file, something is buggy!")
            return default_config
    except FileNotFoundError:
            logger.error("File not found! Check nhi-ignore.yaml or run it in its directory")
            return default_config

        
         

