GLOBAL_NON_RESOURCE_ACTIONS = {
    "sts:getcalleridentity",
    "iam:getaccountsummary",
    "iam:generatecredentialreport",
    "iam:getcredentialreport",
    "iam:getaccountpasswordpolicy",
    "iam:getaccountauthorizationdetails",
    "iam:listaccountaliases",
    "iam:listusers",
    "iam:listroles",
    "iam:listgroups",
    "iam:listpolicies",
    "iam:listopenidconnectproviders",
    "iam:listsamlproviders",
    "iam:listvirtualmfadevices",
    "ec2:getaccountattributes",
    "ec2:describeregions",
    "ec2:describeavailabilityzones",
    "ec2:describeinstances",
    "ec2:describeinstancetypes",
    "ec2:describesecuritygroups",
    "ec2:describevpcs",
    "ec2:describesubnets",
    "ec2:describevolumes",
    "ec2:describesnapshots",
    "ec2:describeimages",
    "ec2:describekeypairs",
    "ec2:describenetworkinterfaces",
    "ec2:describeaddresses",
    "cloudtrail:lookupevents",
    "cloudtrail:describetrails",
    "cloudtrail:getTrailstatus",
    "s3:listallmybuckets",
    "s3:getaccountpublicaccessblock",
    "rds:describedbinstances",
    "rds:describedbclusters",
    "rds:describedbsnapshots",
    "lambda:listfunctions",
    "lambda:listlayers",
    "dynamodb:listtables",
    "dynamodb:describelimits",
    "cloudwatch:listmetrics",
    "cloudwatch:describealarms",
    "logs:describeloggroups",
    "logs:describemetricfilters",
    "ecs:listclusters",
    "ecs:listtaskdefinitions",
    "eks:listclusters",
    "sns:listtopics",
    "sns:listsubscriptions",
    "sqs:listqueues",
    "cloudformation:describestacks",
    "cloudformation:liststacks",
    "route53:listhostedzones",
    "acm:listcertificates",
    "elasticloadbalancing:describeloadbalancers",
    "elasticloadbalancing:describetargetgroups",
    "autoscaling:describeautoscalinggroups",
    "kms:listkeys",
    "kms:listaliases",
    "secretsmanager:listsecrets",
    "organizations:listaccounts",
    "organizations:describeorganization",
}
 
RESOURCE_SCOPED_ACTIONS = {
    # S3 (Bucket-level scope)
    "s3:listbucket",
    "s3:listbucketversions",
    "s3:listbucketmultipartuploads",
    "s3:getbucketpolicy",
    "s3:getbucketacl",
    "s3:getbucketlocation",
    "s3:getobject",
    "s3:getobjectversion",
    "s3:putobject",
    "s3:deleteobject",
    # Secrets Manager & KMS
    "secretsmanager:describesecret",
    "secretsmanager:listsecretversionids",
    "secretsmanager:getsecretvalue",
    "kms:describekey",
    "kms:listgrants",
    "kms:listresourcetags",
    "kms:decrypt",
    "kms:encrypt",
    "kms:generatedatakey",
    # IAM Resource-Scoped Listings
    "iam:listattacheduserpolicies",
    "iam:listattachedrolepolicies",
    "iam:listattachedgrouppolicies",
    "iam:listuserpolicies",
    "iam:listrolepolicies",
    "iam:listgrouppolicies",
    "iam:getrole",
    "iam:getuser",
    "iam:getpolicy",
    "iam:getpolicyversion",
    "iam:listpolicyversions",
    "iam:listrolepolicies",
    "iam:listinstanceprofilesforrole",
    "iam:getrolepolicy",
    "iam:getuserpolicy",
    # Databases & Compute
    "dynamodb:describetable",
    "dynamodb:describetimetolive",
    "dynamodb:getitem",
    "dynamodb:putitem",
    "dynamodb:query",
    "dynamodb:scan",
    "rds:describedbinstances",  # when scoped to a specific instance ARN, not global list
    "rds:modifydbinstance",
    "rds:deletedbinstance",
    "lambda:listversionsbyfunction",
    "lambda:listaliases",
    "lambda:getfunction",
    "lambda:invokefunction",
    "lambda:updatefunctioncode",
    "ec2:describeinstanceattribute",
    "ec2:terminateinstances",
    "ec2:stopinstances",
    "ec2:startinstances",
    "ecs:describeservices",
    "ecs:describetasks",
    "ecs:updateservice",
    "eks:describecluster",
    # Messaging
    "sqs:listdeadlettersourcequeues",
    "sqs:listqueuearns",
    "sqs:getqueueattributes",
    "sqs:sendmessage",
    "sqs:deletemessage",
    "sns:listtagsforresource",
    "sns:publish",
    "sns:subscribe",
    # Logging / observability, when scoped to a specific resource
    "logs:getlogevents",
    "logs:filterlogevents",
    "cloudwatch:getmetricdata",
    "cloudwatch:getmetricstatistics",
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
    if isinstance(resources, str):
        resources_list = [resources]
    elif isinstance(resources, list):
        resources_list = resources
    else:
        return []

    worst_finding = None
    for resource in resources_list:
        classification = classify_resources(resource)
        if classification == "UNCONSTRAINED":
            return [{"Resource": resource, "Type": "UNCONSTRAINED"}]
        elif classification == "SCOPED_PREFIX" and worst_finding is None:
            worst_finding = {"Resource": resource, "Type": "SCOPED_PREFIX"}

    return [worst_finding] if worst_finding else []


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