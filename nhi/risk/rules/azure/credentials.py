from datetime import datetime, timezone


def analyze_stale_sp_credentials(identities, max_validity_days=180):
    findings = []
    if not isinstance(identities, list):
        return findings

    now = datetime.now(timezone.utc)

    for identity in identities:
        if not isinstance(identity, dict):
            continue

        sp_name = identity.get("displayName") or identity.get("appId") or identity.get("id") or "Unknown"
        credentials = (identity.get("passwordCredentials") or []) + (identity.get("keyCredentials") or [])

        for cred in credentials:
            if not isinstance(cred, dict):
                continue

            key_id = cred.get("keyId")
            start_date = cred.get("startDateTime")
            end_date = cred.get("endDateTime")

            # Check 1: Credential has no expiration (never expires)
            if not end_date:
                findings.append({
                    "RuleID": "AZURE_05",
                    "Severity": "MEDIUM",
                    "IdentityType": "ServicePrincipal",
                    "IdentityName": sp_name,
                    "Finding": "Service Principal Credential Never Expires",
                    "TargetID": key_id,
                })
                continue

            try:
                start_dt = datetime.fromisoformat(str(start_date).replace("Z", "+00:00")) if start_date else None
                end_dt = datetime.fromisoformat(str(end_date).replace("Z", "+00:00"))

                # Check 2: Credential validity window > 180 days or active age > 180 days
                if start_dt:
                    validity_days = (end_dt - start_dt).days
                    age_days = (now - start_dt).days

                    if validity_days > max_validity_days or age_days >= max_validity_days:
                        findings.append({
                            "RuleID": "AZURE_05",
                            "Severity": "MEDIUM",
                            "IdentityType": "ServicePrincipal",
                            "IdentityName": sp_name,
                            "Finding": f"Stale or Overly Long-Lived Service Principal Credential (Age: {age_days}d, Lifetime: {validity_days}d > {max_validity_days}d)",
                            "TargetID": key_id,
                            "AgeInDays": age_days,
                        })
            except Exception:
                continue

    return findings
