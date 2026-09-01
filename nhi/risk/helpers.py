GLOBAL_NON_RESOURCE_ACTIONS = {
    "sts:getcalleridentity",
    "iam:getaccountsummary",
    "iam:generatecredentialreport",
    "ec2:getaccountattributes",
    "cloudtrail:lookupevents",
}

RESOURCE_SCOPED_ACTIONS = {
    # S3 (Bucket-level scope)
    "s3:listbucket",
    "s3:listbucketversions",
    "s3:listbucketmultipartuploads",
    # Secrets Manager & KMS
    "secretsmanager:describesecret",
    "secretsmanager:listsecretversionids",
    "kms:describekey",
    "kms:listgrants",
    "kms:listresourcetags",
    # IAM Resource-Scoped Listings
    "iam:listattacheduserpolicies",
    "iam:listattachedrolepolicies",
    "iam:listattachedgrouppolicies",
    "iam:listuserpolicies",
    "iam:listrolepolicies",
    "iam:listgrouppolicies",
    # Databases & Compute
    "dynamodb:describetable",
    "dynamodb:describetimetolive",
    "lambda:listversionsbyfunction",
    "lambda:listaliases",
    # Messaging
    "sqs:listdeadlettersourcequeues",
    "sqs:listqueuearns",
    "sns:listtagsforresource",
}



def classify_resources(resource):
    if not isinstance(resource, str):
        return None
    if resource == "*" or resource == "arn:aws:*:*:*:*":
        return "UNCONSTRAINED"
    if resource.startswith("arn:aws:iam::"):
        parts = resource.split(":", 5)
        if len(parts) == 6 and "/" in parts[5]:
            resource_type, resource_name = parts[5].split("/", 1)
            if resource_name == "*":
                return "UNCONSTRAINED"
    if "*" in resource:
        if resource.startswith("arn:aws:") and not resource.startswith("arn:aws:*:"):
            return "SCOPED_PREFIX"
        return "UNCONSTRAINED"
    return "SPECIFIC"


def analyze_resources(resources):
    resource_findings = []
    if isinstance(resources, str):
        resources_list = [resources]
    elif isinstance(resources, list):
        resources_list = resources
    else:
        return resource_findings

    for resource in resources_list:
        classification = classify_resources(resource)
        if classification in ("UNCONSTRAINED", "SCOPED_PREFIX"):
            resource_findings.append({"Resource": resource, "Type": classification})
            break

    return resource_findings


def match_action(actions, check):
    action_findings = []
    if isinstance(actions, str):
        actions_list = [actions]
    elif isinstance(actions, list):
        actions_list = actions
    else:
        return action_findings

    for action in actions_list:
        if action == "*" or action == "iam:*" or check in action:
            action_findings.append({"Action": action})

    return action_findings


def analyze_actions(actions):
    action_findings = []
    if isinstance(actions, str):
        if "*" in actions:
            action_findings.append({"Action": actions})
    elif isinstance(actions, list):
        for action in actions:
            if "*" in action:
                action_findings.append({"Action": action})
                break
    return action_findings


def has_passed_to_service_condition(condition_block):
    if not condition_block or not isinstance(condition_block, dict):
        return False
    for operator, criteria in condition_block.items():
        if isinstance(criteria, dict) and "iam:PassedToService" in criteria:
            return True
    return False


def is_non_resource_action(action: str) -> bool:
    if not isinstance(action, str):
        return False

    action_lower = action.strip().lower()

    if action_lower.endswith(":*") or action_lower == "*":
        return False

    if action_lower in RESOURCE_SCOPED_ACTIONS:
        return False

    if action_lower in GLOBAL_NON_RESOURCE_ACTIONS:
        return True

    if ":" in action_lower:
        _service, api = action_lower.split(":", 1)
        if api.startswith("describe") or api.startswith("list"):
            return True

    return False


def are_all_actions_non_resource(actions) -> bool:
    if isinstance(actions, str):
        actions = [actions]
    elif not isinstance(actions, list) or not actions:
        return False

    return all(is_non_resource_action(act) for act in actions)