from datetime import datetime, timezone
def analyze_stale_access_keys(user_access_keys,user_name):
    findings = []
    now = datetime.now(timezone.utc)
    for key in user_access_keys:
        days = now - datetime.fromisoformat(str(key['CreateDate']))
        status = key.get('Status')
        if status not in ("Active" , "Inactive"):
             continue
        if(days.days>=90):            
                findings.append({
                "RuleID": "IAM_11",
                "Severity":     "HIGH" if status == 'Active' else "LOW",
                "IdentityType": "User",
                "IdentityName": user_name,
                "Finding":      "Stale Access Key (>90 days old)",
                "TargetID":     key.get("AccessKeyId"),
                "AgeInDays":    days.days,
                "KeyStatus": status
                }
            )
    return findings

def analyze_unused_keys(user_access_keys, user_name):
  findings = []
  now = datetime.now(timezone.utc)

  for key in user_access_keys:
    if key.get('Status') != 'Active':
      continue

    key_id = key.get('AccessKeyId')
    last_used_info = key.get('AccessKeyLastUsed') or {}
    last_used_date = last_used_info.get('LastUsedDate')

    # Branch 1: Key HAS been used at least once
    if last_used_date is not None:
      last_used_dt = datetime.fromisoformat(str(last_used_date))
      days_unused = (now - last_used_dt).days

      if days_unused >= 30:
        findings.append({
            "RuleID": "IAM_12",
            'Severity': 'HIGH',
            'IdentityType': 'User',
            'IdentityName': user_name,
            'Finding': 'Key Unused in 30 days',
            'TargetID': key_id,
            'AgeInDays': days_unused,
            'KeyStatus': key.get('Status'),
        })

    # Branch 2: Key was NEVER used -> Calculate age from CreateDate
    else:
      create_dt = datetime.fromisoformat(str(key['CreateDate']))
      key_age = (now - create_dt).days

      if key_age >= 30:
        findings.append({
           "RuleID": "IAM_12",
            'Severity': 'HIGH',
            'IdentityType': 'User',
            'IdentityName': user_name,
            'Finding': 'Key Unused since its inception',
            'TargetID': key_id,
            'AgeInDays': key_age,
            'KeyStatus': key.get('Status'),
        })

  return findings