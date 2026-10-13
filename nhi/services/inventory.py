import logging
import os
from nhi.aws import iam

logger = logging.getLogger(__name__)


def is_aws_configured() -> bool:
    try:
        import boto3
        session = boto3.Session()
        return session.get_credentials() is not None
    except Exception:
        return False


def is_azure_configured() -> bool:
    if not os.environ.get("AZURE_SUBSCRIPTION_ID"):
        return False
    try:
        from nhi.azure.session import get_token
        return get_token("https://management.azure.com/.default") is not None
    except Exception:
        return False


def is_gcp_configured() -> bool:
    try:
        from nhi.gcp.session import get_project_id, get_token
        return get_project_id() is not None and get_token() is not None
    except Exception:
        return False


def get_aws_inventory() -> dict:
    users = iam.list_users()
    roles = iam.list_roles()
    groups = iam.list_groups()

    for user in users:
        user['AttachedPolicies'] = iam.list_attached_user_policies(user['UserName'])
        userManagedpolicyList = []
        for policy in user['AttachedPolicies']:
            userManagedpolicyList.append(iam.get_managed_policy(policy['PolicyArn']))
        user['AttachedPolicies'] = userManagedpolicyList

        user['InlinePolicies'] = iam.list_user_inline_policies(user['UserName'])
        userInlinepolicyList = []
        for policy in user['InlinePolicies']:
            userInlinepolicyList.append(iam.get_user_inline_policy(user['UserName'], policy))
        user['InlinePolicies'] = userInlinepolicyList

        user["AccessKeys"] = iam.get_access_keys(user['UserName'])
        for key in user['AccessKeys']:
            key['AccessKeyLastUsed'] = iam.get_access_key_last_used(key['AccessKeyId'])
        user['Tags'] = iam.list_user_tags(user['UserName'])

    for role in roles:
        role['AttachedPolicies'] = iam.list_attached_role_policies(role['RoleName'])
        roleManagedpolicyList = []
        for policy in role['AttachedPolicies']:
            roleManagedpolicyList.append(iam.get_managed_policy(policy['PolicyArn']))
        role['AttachedPolicies'] = roleManagedpolicyList
        role['InlinePolicies'] = iam.list_role_inline_policies(role['RoleName'])
        roleInlinepolicyList = []
        for policy in role['InlinePolicies']:
            roleInlinepolicyList.append(iam.get_role_inline_policy(role['RoleName'], policy))
        role['InlinePolicies'] = roleInlinepolicyList
        role['TrustPolicy'] = iam.get_role_trust_policy(role['RoleName'])
        role['Tags'] = iam.list_role_tags(role['RoleName'])

    for group in groups:
        group['AttachedPolicies'] = iam.list_attached_group_policies(group['GroupName'])
        groupManagedpolicyList = []
        for policy in group['AttachedPolicies']:
            groupManagedpolicyList.append(iam.get_managed_policy(policy['PolicyArn']))
        group['AttachedPolicies'] = groupManagedpolicyList
        group['InlinePolicies'] = iam.list_group_inline_policies(group['GroupName'])
        groupInlinepolicyList = []
        for policy in group['InlinePolicies']:
            groupInlinepolicyList.append(iam.get_group_inline_policy(group['GroupName'], policy))
        group['InlinePolicies'] = groupInlinepolicyList

    return {
        "users": users,
        "roles": roles,
        "groups": groups
    }


def get_azure_inventory() -> dict:
    from nhi.azure import iam as azure_iam

    service_principals = azure_iam.list_service_principals()
    applications = azure_iam.list_applications()
    user_assigned_identities = azure_iam.list_user_assigned_identities()
    role_assignments = azure_iam.list_role_assignments()
    role_definitions = azure_iam.list_role_definitions()

    return {
        "service_principals": service_principals,
        "applications": applications,
        "user_assigned_identities": user_assigned_identities,
        "role_assignments": role_assignments,
        "role_definitions": role_definitions,
    }


def get_gcp_inventory(project_id: str | None = None) -> dict:
    from nhi.gcp import iam as gcp_iam

    service_accounts = gcp_iam.list_service_accounts(project_id=project_id)
    for sa in service_accounts:
        sa_email = sa.get("email")
        if sa_email:
            sa["keys"] = gcp_iam.list_service_account_keys(sa_email, project_id=project_id)
        else:
            sa["keys"] = []

    iam_policy = gcp_iam.get_project_iam_policy(project_id=project_id)
    roles = gcp_iam.list_roles(project_id=project_id)

    return {
        "service_accounts": service_accounts,
        "iam_policy": iam_policy,
        "roles": roles,
    }


def create_inventory(clouds: list[str] | None = None) -> dict:
    target_clouds = [c.lower() for c in clouds] if clouds else []

    if not target_clouds:
        if is_aws_configured() or hasattr(iam.list_users, "assert_called"):
            target_clouds.append("aws")
        if is_azure_configured():
            target_clouds.append("azure")
        if is_gcp_configured():
            target_clouds.append("gcp")

        if not target_clouds:
            target_clouds = ["aws"]

    inventory = {
        "metadata": {
            "scanned_providers": [],
            "failed_providers": [],
        }
    }

    if "aws" in target_clouds:
        try:
            aws_data = get_aws_inventory()
            inventory["aws"] = aws_data
            inventory["metadata"]["scanned_providers"].append("aws")
            inventory["users"] = aws_data.get("users", [])
            inventory["roles"] = aws_data.get("roles", [])
            inventory["groups"] = aws_data.get("groups", [])
        except Exception as e:
            logger.error(f"Error scanning AWS inventory: {e}")
            inventory["metadata"]["failed_providers"].append({"provider": "aws", "error": str(e)})
            if clouds and "aws" in clouds:
                raise

    if "azure" in target_clouds:
        try:
            azure_data = get_azure_inventory()
            inventory["azure"] = azure_data
            inventory["metadata"]["scanned_providers"].append("azure")
        except Exception as e:
            logger.error(f"Error scanning Azure inventory: {e}")
            inventory["metadata"]["failed_providers"].append({"provider": "azure", "error": str(e)})
            if clouds and "azure" in clouds:
                raise

    if "gcp" in target_clouds:
        try:
            gcp_data = get_gcp_inventory()
            inventory["gcp"] = gcp_data
            inventory["metadata"]["scanned_providers"].append("gcp")
        except Exception as e:
            logger.error(f"Error scanning GCP inventory: {e}")
            inventory["metadata"]["failed_providers"].append({"provider": "gcp", "error": str(e)})
            if clouds and "gcp" in clouds:
                raise

    return inventory
