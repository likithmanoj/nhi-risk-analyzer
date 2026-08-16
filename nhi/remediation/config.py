import yaml
import logging
import sys

logging.basicConfig(
    level=logging.INFO,
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
    except (FileNotFoundError, yaml.YAMLError) as e:
        logger.critical(f"Safety config failed to load: {e}")
        raise RuntimeError('Safety config failed to load in nhi/remediation/config') from e


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

    
    rule_id = finding.get("RuleID")
    identity_type = (finding.get("IdentityType") or "").lower()
    identity_name = finding.get("IdentityName")
    target_id = finding.get("TargetID")

    
    def _rule_matches(exempted_rules: list) -> bool:
        if not isinstance(exempted_rules, list):
            return False
        return "*" in exempted_rules or rule_id in exempted_rules

   
    if identity_type == "user":
        ignore_users = ignore_config.get("ignore_users") or []
        for user in ignore_users:
            if user.get("name") == identity_name and _rule_matches(user.get("rules")):
                logger.info(
                    f"Skipping User '{identity_name}' for rule '{rule_id}' (nhi-ignore exemption)."
                )
                return True

    
    elif identity_type == "role":
        ignore_roles = ignore_config.get("ignore_roles") or []
        for role in ignore_roles:
            if role.get("name") == identity_name and _rule_matches(role.get("rules")):
                logger.info(
                    f"Skipping Role '{identity_name}' for rule '{rule_id}' (nhi-ignore exemption)."
                )
                return True

  
    elif identity_type == "group":
        ignore_groups = ignore_config.get("ignore_groups") or []
        for group in ignore_groups:
            if group.get("name") == identity_name and _rule_matches(group.get("rules")):
                logger.info(
                    f"Skipping Group '{identity_name}' for rule '{rule_id}' (nhi-ignore exemption)."
                )
                return True

   
    if target_id:
        ignore_access_keys = ignore_config.get("ignore_access_keys") or []
        for key in ignore_access_keys:
            if key.get("id") == target_id and _rule_matches(key.get("rules")):
                logger.info(
                    f"Skipping Access Key '{target_id}' for rule '{rule_id}' (nhi-ignore exemption)."
                )
                return True

    
    return False 
      

        
         

