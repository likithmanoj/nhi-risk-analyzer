from nhi.risk.helpers import (
    GLOBAL_NON_RESOURCE_ACTIONS,RESOURCE_SCOPED_ACTIONS, is_non_resource_action)


def analyze_resource(resource) -> bool:
    if isinstance(resource, str):
        resource_list = [resource]
    elif isinstance(resource, list):
        resource_list = resource
    else:
        return False

    for res in resource_list:
        if isinstance(res, str) and res.strip() == "*":
            return True
    return False


def partition_actions(actions):
    discovery_actions = []
    scoped_actions = []

    if isinstance(actions, str):
        actions_list = [actions]
    elif isinstance(actions, list):
        actions_list = actions
    else:
        return [], []

    for action in actions_list:
        if is_non_resource_action(action):
            discovery_actions.append(action)
        else:
            scoped_actions.append(action)

    return discovery_actions, scoped_actions


def split_policy_statement(
    policy_doc: dict,
    target_arn_placeholder: str = "arn:aws:*:*:*:placeholder/*",
) -> dict:
    if not isinstance(policy_doc, dict):
        return {}

    new_policy = {}
    for key, val in policy_doc.items():
        if key != "Statement":
            new_policy[key] = val

    statements = policy_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    elif not isinstance(statements, list):
        new_policy["Statement"] = []
        return new_policy

    new_statements = []

    for statment in statements:
        if not isinstance(statment, dict):
            continue

        if statment.get("Effect") != "Allow" or not analyze_resource(statment.get("Resource")):
            new_statements.append(statment)
        else:
            discovery, scoped = partition_actions(statment.get("Action"))
            base_sid = statment.get("Sid", "Statement")

            if len(discovery) > 0 and len(scoped) > 0:
                discovery_statment = {
                    "Sid": base_sid + "Discovery",
                    "Effect": "Allow",
                    "Action": discovery,
                    "Resource": "*",
                }
                scoped_statment = {
                    "Sid": base_sid + "Scoped",
                    "Effect": "Allow",
                    "Action": scoped,
                    "Resource": target_arn_placeholder,
                }

                if "Condition" in statment:
                    discovery_statment["Condition"] = statment["Condition"]
                    scoped_statment["Condition"] = statment["Condition"]

                new_statements.append(discovery_statment)
                new_statements.append(scoped_statment)

            elif len(scoped) > 0 and len(discovery) == 0:
                scoped_statment = {
                    "Sid": base_sid,
                    "Effect": "Allow",
                    "Action": scoped,
                    "Resource": target_arn_placeholder,
                }
                if "Condition" in statment:
                    scoped_statment["Condition"] = statment["Condition"]

                new_statements.append(scoped_statment)

            else:
                new_statements.append(statment)

    new_policy["Statement"] = new_statements
    return new_policy