#iam.py is responsible for encapsulating all AWS IAM operations required by the NHI platform while hiding the underlying boto3 IAM implementation from the rest of the application.

from nhi.aws.session import get_session

def list_users():
    session = get_session()
    iam_client = session.client('iam')
    response = iam_client.list_users()
    return response['Users']

def list_roles():
    session = get_session()
    iam_client = session.client('iam')
    response = iam_client.list_roles()
    return response['Roles']

def list_groups():
    session = get_session()
    iam_client = session.client('iam')
    response = iam_client.list_groups()
    return response['Groups']


