#session.py is responsible for creating and managing an authenticated AWS boto3 Session using the project's configured authentication mechanism (currently STS AssumeRole). It abstracts authentication from the rest of the application
import boto3
from nhi.config import ROLE_ARN
import boto3.session

_cached_session = None


def get_session():
    global _cached_session
    if _cached_session is not None:
        return _cached_session
    session_client =  boto3.client('sts')
    response = session_client.assume_role(
        # TODO:
# For learning purposes, retrieve the Role ARN dynamically using the IAM API.
# In production, inject the Role ARN via configuration (Terraform output,
# environment variables, or deployment pipeline) to avoid the extra API call.
        RoleArn = ROLE_ARN,
        RoleSessionName = 'sessionForNHI' #to be changed later
    )
    credentials = response['Credentials']
    _cached_session =  boto3.session.Session(aws_access_key_id = credentials['AccessKeyId'], aws_secret_access_key = credentials['SecretAccessKey'], aws_session_token  = credentials['SessionToken'])
    return _cached_session