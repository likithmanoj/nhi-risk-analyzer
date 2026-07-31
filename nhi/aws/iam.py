#iam.py is responsible for encapsulating all AWS IAM operations required by the NHI platform while hiding the underlying boto3 IAM implementation from the rest of the application.

from nhi.aws.session import get_session

def list_users():
    session = get_session()
    iam_client = session.client('iam')
    paginator = iam_client.get_paginator('list_users')
    users = []
    for page in paginator.paginate():
        users.extend(page['Users'])
    return users
def list_roles():
    session = get_session()
    iam_client = session.client('iam')
    paginator = iam_client.get_paginator('list_roles')
    roles = []
    for page in paginator.paginate():
        roles.extend(page['Roles'])
    return roles
def list_groups():
    session = get_session()
    iam_client = session.client('iam')
    paginator = iam_client.get_paginator('list_groups')
    groups = []
    for page in paginator.paginate():
        groups.extend(page['Groups'])
    return groups
def list_policies():
    session = get_session()
    iam_client = session.client('iam')
    paginator = iam_client.get_paginator('list_policies')
    policies = []
    for page in paginator.paginate():
        policies.extend(page['Policies'])
    return policies
def list_attached_user_policies(username):
    session = get_session()
    iam_client = session.client('iam')
    paginator = iam_client.get_paginator('list_attached_user_policies')
    user_attached_policies = []
    for page in paginator.paginate(UserName = username):
        user_attached_policies.extend(page['AttachedPolicies'])
    return user_attached_policies
def list_attached_role_policies(rolename):
    session = get_session()
    iam_client = session.client('iam')
    paginator = iam_client.get_paginator('list_attached_role_policies')
    role_attached_policies = []
    for page in paginator.paginate(RoleName = rolename):
        role_attached_policies.extend(page['AttachedPolicies'])
    return role_attached_policies
def list_user_inline_policies(username):
    session = get_session()
    iam_client = session.client('iam')
    paginator = iam_client.get_paginator('list_user_policies')
    user_inline_policies = []
    for page in paginator.paginate(UserName = username):
        user_inline_policies.extend(page['PolicyNames'])
    return user_inline_policies
def list_role_inline_policies(rolename):
    session = get_session()
    iam_client = session.client('iam')
    paginator = iam_client.get_paginator('list_role_policies')
    role_inline_policies = []
    for page in paginator.paginate(RoleName = rolename):
        role_inline_policies.extend(page['PolicyNames'])
    return role_inline_policies
def get_user_inline_policy(username, policyname):
    response = get_session().client('iam').get_user_policy(UserName = username, PolicyName = policyname)
    return {
        "PolicyName" : response["PolicyName"],
        "PolicyDocument": response["PolicyDocument"]}
def get_role_inline_policy(rolename, policyname):
    response = get_session().client('iam').get_role_policy(RoleName = rolename, PolicyName = policyname)
    return {
        "PolicyName" : response["PolicyName"],
        "PolicyDocument": response["PolicyDocument"]}
def get_managed_policy(policy_arn):
    session = get_session()
    iam_client = session.client("iam")

    policy = iam_client.get_policy(
        PolicyArn=policy_arn
    )["Policy"]

    version = iam_client.get_policy_version(
        PolicyArn=policy_arn,
        VersionId=policy["DefaultVersionId"]
    )["PolicyVersion"]

    return {
        "PolicyName": policy["PolicyName"],
        "PolicyArn": policy["Arn"],
        "PolicyDocument": version["Document"]
    }
def list_attached_group_policies(groupName):
    session = get_session()
    iam_client = session.client('iam')
    paginator = iam_client.get_paginator('list_attached_group_policies')
    group_attached_policies = []
    for page in paginator.paginate(GroupName = groupName):
        group_attached_policies.extend(page['AttachedPolicies'])
    return group_attached_policies
def list_group_inline_policies(groupName):
    session = get_session()
    iam_client = session.client('iam')
    paginator = iam_client.get_paginator('list_group_policies')
    group_inline_policies = []
    for page in paginator.paginate(GroupName = groupName):
        group_inline_policies.extend(page['PolicyNames'])
    return group_inline_policies
def get_group_inline_policy(groupname, policyname):
    response = get_session().client('iam').get_group_policy(GroupName = groupname, PolicyName = policyname)
    return{
        "PolicyName" : response["PolicyName"],
        "PolicyDocument" : response["PolicyDocument"]
    }  
    


   