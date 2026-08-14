import logging
from nhi.aws.iam import update_access_key

logger = logging.getLogger(__name__)


def handle_credential_remediation(finding: dict, dry_run: bool = True) -> bool:
    """Handler for Credential findings (IAM_11, IAM_12)."""
    identity_name = finding.get("IdentityName")
    target_id = finding.get("TargetID")

    if not identity_name or not target_id:
        logger.error(f"Malformed finding missing required identity or target ID: {finding}")
        return False

    if dry_run:
        logger.info(f"[DRY-RUN] Would deactivate key {target_id} for user {identity_name}")
        return True

    response = update_access_key(identity_name, target_id, "Inactive")
    if isinstance(response, dict) and response.get("HTTPStatusCode") == 200:
        logger.info(f"Successfully deactivated access key {target_id} for user {identity_name}")
        return True

    logger.error(f"Failed to deactivate access key {target_id} for user {identity_name}")
    return False