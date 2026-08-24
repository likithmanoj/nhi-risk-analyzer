import logging
from nhi.aws.iam import tag_user, tag_role

logger = logging.getLogger(__name__)


def remediate_missing_tags(finding, dry_run=False):
    identity_type = finding.get("IdentityType")
    identity_name = finding.get("IdentityName")
    missing_tags = finding.get("MissingTags", [])
    tags_to_apply = []
    for tag_key in missing_tags:
        tags_to_apply.append({
            "Key": tag_key,
            "Value": "Unassigned"
        })
    if dry_run:
        logger.info(
            f"[DRY-RUN] Would attach tags {missing_tags} to {identity_type} '{identity_name}'."
        )
        return True
    if identity_type == "User":
        return tag_user(identity_name, tags_to_apply)
    elif identity_type == "Role":
        return tag_role(identity_name, tags_to_apply)
    else:
        logger.warning(f"Unsupported identity type for tagging: {identity_type}")
        return False