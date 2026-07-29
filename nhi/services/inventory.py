from nhi.aws import iam

def create_inventory():
    users = iam.list_users()
    roles = iam.list_roles()
    groups = iam.list_groups()

    for user in users:
        user['AttachedPolicies'] = iam.list_attached_user_policies(user['UserName'])
        user['InlinePolicies'] = iam.list_user_inline_policies(user['UserName'])
        userpolicyList = []
        for policy in user['InlinePolicies']:
            userpolicyList.append(iam.get_user_inline_policy(user['UserName'],policy))
        user['InlinePolicies'] = userpolicyList

    for role in roles:
        role['AttachedPolicies'] = iam.list_attached_role_policies(role['RoleName'])
        role['InlinePolicies'] = iam.list_role_inline_policies(role['RoleName'])
        rolepolicyList = []
        for policy in role['InlinePolicies']:
            rolepolicyList.append(iam.get_role_inline_policy(role['RoleName'],policy))
        role['InlinePolicies'] = rolepolicyList 

    return {
        "users": users,
        "roles": roles,
        "groups": groups
    }