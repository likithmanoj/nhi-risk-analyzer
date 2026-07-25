#session.py is responsible for creating and managing an authenticated AWS boto3 Session using the project's configured authentication mechanism (currently STS AssumeRole). It abstracts authentication from the rest of the application

from config import ROLE_ARN
