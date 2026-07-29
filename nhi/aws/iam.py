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