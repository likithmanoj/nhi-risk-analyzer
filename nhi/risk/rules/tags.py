MANDATORY_TAGS = ["Owner", "Environment"]


def analyze_mandatory_tags(identity, identity_type, required_tags=MANDATORY_TAGS):
    if identity_type == "User":
        name = identity.get("UserName")
    else:
        name = identity.get("RoleName")
    raw_tags = identity.get("Tags", [])
    existing_keys = []
    
    if raw_tags:
        for tag in raw_tags:
            if "Key" in tag:
                existing_keys.append(tag["Key"])

    missing_tags = []
    for required in required_tags:
        if required not in existing_keys:
            missing_tags.append(required)

    if len(missing_tags) > 0:
        return [
            {
                "RuleID": "TAG_01",
                "Severity": "LOW",
                "IdentityType": identity_type,
                "IdentityName": name,
                "Finding": f"Missing Mandatory Governance Tags: {missing_tags}",
                "MissingTags": missing_tags,
            }
        ]
    else:
        return []

