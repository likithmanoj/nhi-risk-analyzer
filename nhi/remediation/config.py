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
    "ignore_groups": [],
    "ignore_access_keys": [],
    }
    try:
        with open(config_path,"r") as f:
            ignore_data = yaml.safe_load(f)
            data = ignore_data if isinstance(ignore_data, dict) else {}
            exemptions = data.get("exemptions") or {}
            response = {
            "ignore_users" : exemptions.get('users') or [],
            "ignore_roles" : exemptions.get('roles') or [],
            "ignore_groups": exemptions.get("groups") or [],
            "ignore_access_keys" : exemptions.get('access_keys') or []
            }
            return response
    except yaml.YAMLError:
            logger.error("Check nhi-ignore.yaml file, something is buggy!")
            return default_config
    except FileNotFoundError:
            logger.error("File not found! Check nhi-ignore.yaml or run it in its directory")
            return default_config


def is_ignored(finding: dict, ignore_config: dict) -> bool:
    """
    Evaluates whether a finding should be exempted from remediation
    based on the loaded nhi-ignore configuration.

    Args:
        finding (dict): Finding payload from scanner.
        ignore_config (dict): Parsed config dict from load_ignore_config().

    Returns:
        bool: True if finding matches an exemption rule (skip), False otherwise.
    """
    if not isinstance(finding, dict) or not isinstance(ignore_config, dict):
        return False

    # Safely extract core fields
    rule_id = finding.get("RuleID")
    identity_type = (finding.get("IdentityType") or "").lower()
    identity_name = finding.get("IdentityName")
    target_id = finding.get("TargetID")

    # Internal helper to evaluate wildcard '*' or specific RuleID matches
    def _rule_matches(exempted_rules: list) -> bool:
        if not isinstance(exempted_rules, list):
            return False
        return "*" in exempted_rules or rule_id in exempted_rules

    # 1. Check User Exemptions
    if identity_type == "user":
        ignore_users = ignore_config.get("ignore_users") or []
        for user in ignore_users:
            if user.get("name") == identity_name and _rule_matches(user.get("rules")):
                logger.info(
                    f"Skipping User '{identity_name}' for rule '{rule_id}' (nhi-ignore exemption)."
                )
                return True

    # 2. Check Role Exemptions
    elif identity_type == "role":
        ignore_roles = ignore_config.get("ignore_roles") or []
        for role in ignore_roles:
            if role.get("name") == identity_name and _rule_matches(role.get("rules")):
                logger.info(
                    f"Skipping Role '{identity_name}' for rule '{rule_id}' (nhi-ignore exemption)."
                )
                return True

    # 3. Check Group Exemptions
    elif identity_type == "group":
        ignore_groups = ignore_config.get("ignore_groups") or []
        for group in ignore_groups:
            if group.get("name") == identity_name and _rule_matches(group.get("rules")):
                logger.info(
                    f"Skipping Group '{identity_name}' for rule '{rule_id}' (nhi-ignore exemption)."
                )
                return True

    # 4. Check Access Key / Resource Exemptions (if TargetID exists)
    if target_id:
        ignore_access_keys = ignore_config.get("ignore_access_keys") or []
        for key in ignore_access_keys:
            if key.get("id") == target_id and _rule_matches(key.get("rules")):
                logger.info(
                    f"Skipping Access Key '{target_id}' for rule '{rule_id}' (nhi-ignore exemption)."
                )
                return True

    # Default fallback: No rules matched, proceed with remediation
    return False 
      

        
         

