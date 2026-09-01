import logging
from nhi.remediation.config import is_ignored, load_ignore_config
from nhi.remediation.handlers.credential import handle_credential_remediation
from nhi.remediation.handlers.policy import handle_policy_remediation
from nhi.remediation.handlers.tags import remediate_missing_tags

HANDLER_MAP = {
    "IAM_01": handle_policy_remediation,
    "IAM_02": handle_policy_remediation,
    "IAM_03": handle_policy_remediation,
    "IAM_04": handle_policy_remediation,
    "IAM_05": handle_policy_remediation,
    "IAM_06": handle_policy_remediation,
    "IAM_07": handle_policy_remediation,
    "IAM_08": handle_policy_remediation,
    "IAM_09": handle_policy_remediation,
    "IAM_10": handle_policy_remediation,
    "IAM_11": handle_credential_remediation,
    "IAM_12": handle_credential_remediation,
    "IAM_14": handle_policy_remediation,
    "IAM_15": handle_policy_remediation,
    "IAM_16": handle_policy_remediation,
    "TAG_01": remediate_missing_tags,
}

logger = logging.getLogger(__name__)


def dispatch_remediation(findings: list, dry_run: bool = True) -> dict:
    skipped = failed = remediated = 0
    manual_review_required = 0
    current_exemption = load_ignore_config("nhi-ignore.yaml")

    for finding in findings:
        rule_id = finding.get("RuleID") if isinstance(finding, dict) else "UNKNOWN"

        if finding.get("RemediationEligible") is False or (
            finding.get("IdentityType") == "Group"
            and rule_id.startswith("IAM_")
            and rule_id not in ("IAM_11", "IAM_12")
        ):
            manual_review_required += 1
            logger.info(f"Manual review required (not auto-remediable): {finding}")
            continue

        try:
            ignored = is_ignored(finding, current_exemption)
            if ignored:
                skipped += 1
                logger.info(f"This finding was found to be ignored:{finding}")
                continue

            handler = HANDLER_MAP.get(rule_id)
            if handler:
                if handler(finding, dry_run=dry_run):
                    remediated += 1
                else:
                    failed += 1
            else:
                logger.error(f"No handler registered for this rule: {rule_id}")
                failed += 1
        except Exception as e:
            logger.exception(
                f"Failed to remediate finding for RuleID '{rule_id}': {e}"
            )
            failed += 1

    action_key = "would_remediate" if dry_run else "remediated"
    return {
        "total": len(findings),
        action_key: remediated,
        "manual_review_required": manual_review_required,
        "skipped": skipped,
        "failed": failed,
    }