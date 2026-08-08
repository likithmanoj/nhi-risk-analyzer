from nhi.aws import iam

def create_inventory():
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
            userInlinepolicyList.append(iam.get_user_inline_policy(user['UserName'],policy))
        user['InlinePolicies'] = userInlinepolicyList

        user["AccessKeys"] = iam.get_access_keys(user['UserName'])
        for key in user['AccessKeys']:
            key['AccessKeyLastUsed'] = iam.get_access_key_last_used(key['AccessKeyId'])

    for role in roles:
        role['AttachedPolicies'] = iam.list_attached_role_policies(role['RoleName'])
        roleManagedpolicyList = []
        for policy in role['AttachedPolicies']:
            roleManagedpolicyList.append(iam.get_managed_policy(policy['PolicyArn']))
        role['AttachedPolicies'] = roleManagedpolicyList
        role['InlinePolicies'] = iam.list_role_inline_policies(role['RoleName'])
        roleInlinepolicyList = []
        for policy in role['InlinePolicies']:
            roleInlinepolicyList.append(iam.get_role_inline_policy(role['RoleName'],policy))
        role['InlinePolicies'] = roleInlinepolicyList
        role['TrustPolicy'] = iam.get_role_trust_policy(role['RoleName'])

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