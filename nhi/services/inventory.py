from nhi.aws import iam

def create_inventory():
    users = iam.list_users()
    roles = iam.list_roles()
    groups = iam.list_groups()

    for user in users:
        user['AttachedPolicies'] = iam.list_attached_user_policies(user['UserName'])

    for role in roles:
        role['AttachedPolicies'] = iam.list_attached_role_policies(role['RoleName'])  

    return {
        "users": users,
        "roles": roles,
        "groups": groups
    }