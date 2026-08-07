from datetime import datetime, timezone
def analyze_stale_access_keys(user_access_keys,user_name):
    findings = []
    now = datetime.now(timezone.utc)
    for key in user_access_keys:
        days = now - datetime.fromisoformat(str(key['CreateDate']))
        status = key['Status']
        if status not in ("Active" , "Inactive"):
             continue
        if(days.days>=90):            
                findings.append({
                "Severity":     "HIGH" if status == 'Active' else "LOW",
                "IdentityType": "User",
                "IdentityName": user_name,
                "Finding":      "Stale Access Key (>90 days old)",
                "TargetID":     key["AccessKeyId"],
                "AgeInDays":    days.days,
                "KeyStatus": status
                }
            )
    return findings