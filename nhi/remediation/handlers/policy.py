import logging
import os
from nhi.aws.iam import set_role_permissions_boundary, set_user_permissions_boundary

logger = logging.getLogger(__name__)


def handle_policy_remediation(finding: dict, dry_run: bool = True) -> bool:
    boundary_arn = os.getenv("NHI_BOUNDARY_POLICY_ARN")
    if not boundary_arn:
        logger.error(
            "Remediation failed: NHI_BOUNDARY_POLICY_ARN environment variable is not set."
        )
        return False

    identity_type = finding.get("IdentityType")
    identity_name = finding.get("IdentityName")

    if not identity_name:
        logger.error("Finding missing 'IdentityName'. Cannot remediate.")
        return False

    if dry_run:
        logger.info(
            f"[DRY-RUN] Would attach permissions boundary {boundary_arn} to {identity_type} '{identity_name}'."
        )
        return True

    if identity_type == "User":
        return set_user_permissions_boundary(identity_name, boundary_arn)
    elif identity_type == "Role":
        return set_role_permissions_boundary(identity_name, boundary_arn)
    else:
        logger.warning(
            f"Manual intervention required: Automated remediation not supported for identity type '{identity_type}' ({identity_name})."
        )
        return False