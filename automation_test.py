from nhi.aws.s3 import upload_file

file_name = "test_file.txt"
with open(file_name, "w") as f:
    f.write("This is a test file for S3 upload.")
upload_file(file_name)


