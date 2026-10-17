from datetime import datetime, timezone


def analyze_stale_service_account_keys(service_accounts, max_age_days=90):
    findings = []
    if not isinstance(service_accounts, list):
        return findings

    now = datetime.now(timezone.utc)

    for sa in service_accounts:
        if not isinstance(sa, dict):
            continue

        sa_email = sa.get("email") or sa.get("displayName") or "Unknown"
        keys = sa.get("keys") or []

        for key in keys:
            if not isinstance(key, dict):
                continue

            # Only inspect user-managed keys (Google-managed SYSTEM_MANAGED rotate automatically)
            key_type = key.get("keyType")
            if key_type != "USER_MANAGED":
                continue

            valid_after = key.get("validAfterTime")
            if not valid_after:
                continue

            try:
                valid_after_dt = datetime.fromisoformat(str(valid_after).replace("Z", "+00:00"))
                age_days = (now - valid_after_dt).days

                if age_days >= max_age_days:
                    key_id = key.get("name", "").split("/")[-1] or key.get("name")
                    findings.append({
                        "RuleID": "GCP_06",
                        "Severity": "MEDIUM",
                        "IdentityType": "ServiceAccount",
                        "IdentityName": sa_email,
                        "Finding": f"Stale User-Managed Service Account Key (> {max_age_days} days old)",
                        "TargetID": key_id,
                        "AgeInDays": age_days,
                        "KeyType": key_type,
                    })
            except Exception:
                continue

    return findings
