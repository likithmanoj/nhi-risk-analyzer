import botocore
from nhi.aws.session import get_session
from nhi.config import BUCKET_NAME


session = get_session()

s3_client= session.client('s3')


file_name = "test_file.txt"
with open(file_name, "w") as f:
    f.write("This is a test file for S3 upload.")

try:
    s3_client.upload_file(file_name, BUCKET_NAME, file_name)
    print(f"File '{file_name}' uploaded to bucket '{BUCKET_NAME}' successfully.")


except botocore.exceptions.ClientError as e:
    print(f"Error uploading file: {e}")

