#Creating the IAM user using variable placeholder
resource "aws_iam_user" "nhi_automation_runner" {

  /*
  SECURITY AUDIT LEDGER
  Owner: Identity Security Automation Team
  Purpose: Non-Human Identity Runner for Secrets Migration Engine
  Compliance: SOP-IAM-01 / Least Privilege Baseline
  */

  name          = "nhi-automation-runner-${var.environment}"
  path          = "/system/"
  force_destroy = true

  tags = {
    Environment = var.environment
  }
}

# Temporary implementation.
# This resource will be removed once the application authenticates using IAM Roles and AWS STS.
# Removing long-lived access keys prevents sensitive credentials from being stored in Terraform state.
resource "aws_iam_access_key" "nhi_runner_keys" {
  user = aws_iam_user.nhi_automation_runner.name
}

data "aws_partition" "current" {}

resource "aws_iam_policy" "role_policy" {
  name        = "${var.project_name}-${var.environment}-runner-policy"
  path        = "/"
  description = "IAM policy for automation runner role to access S3 buckets in ${var.environment} environment"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Allow the automation runner to perform S3 actions on the specified bucket when Python is run we need GetObject and PutObject permissions to read and write files to the S3 bucket
        Action = ["s3:ListBucket", "s3:GetObject", "s3:PutObject"]
        Effect = "Allow"
        Resource = [
          # "arn:${data.aws_partition.current.partition}:s3:::${var.project_name}-${var.environment}-bucket", #Replacing with non json and just making terraform more readable by forcing the arn to point to existing object arns
          # "arn:${data.aws_partition.current.partition}:s3:::${var.project_name}-${var.environment}-bucket/*",
          aws_s3_bucket.nhi_automation_bucket.arn,
        "${aws_s3_bucket.nhi_automation_bucket.arn}/*"]
      },
      {
        # Allow the automation runner to discover IAM identities for inventory collection.
        Action   = ["iam:ListUsers", "iam:ListRoles", "iam:ListGroups", "iam:ListAttachedUserPolicies", "iam:ListAttachedRolePolicies", "iam:ListUserPolicies", "iam:GetUserPolicy", "iam:ListRolePolicies", "iam:GetRolePolicy"]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
} #Replaced the entire code with below policy to remove the IAM user credential and give it least privilege to the IAM user by creating a role and let the iam policy to attach to that role as in fit into that role
#policy should exist as the role needs to have the S3 permissions

resource "aws_iam_policy" "nhi_user_sts_policy" {
  name        = "${var.project_name}-${var.environment}-sts-assume-role-policy"
  path        = "/"
  description = "IAM policy allowing the automation runner to assume the automation IAM role."
  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        #Removed S3 actions to maintain least privilege to the Python user and resource is now pointing to role created.
        Action   = ["sts:AssumeRole"]
        Effect   = "Allow"
        Resource = aws_iam_role.nhi_automation_runner_role.arn
      }
    ]
  })
}

resource "aws_iam_user_policy_attachment" "nhi_runner_policy_attachment" {
  user       = aws_iam_user.nhi_automation_runner.name
  policy_arn = aws_iam_policy.nhi_user_sts_policy.arn
}

#data "aws_caller_identity" "current_user" {} wrote it when I wanted to pull data #   AWS = "arn:aws:iam::${data.aws_caller_identity.current_user.account_id}:user/system/${aws_iam_user.nhi_automation_runner.name}"

# resource "aws_iam_role" "nhi_automation_runner_role" {
#   name = "nhi-automation-runner-role-${var.environment}"
#   assume_role_policy = jsonencode({
#     Version = "2012-10-17"
#     Statement = [
#       {
#         Action = "sts:AssumeRole"
#         Effect = "Allow"
#         Sid    = ""
#         Principal = {
#           #   AWS = "arn:aws:iam::${data.aws_caller_identity.current_user.account_id}:user/system/${aws_iam_user.nhi_automation_runner.name}"
#           # arn was first written to encode the arn but then it could also be directly pointed to the user
#           AWS = aws_iam_user.nhi_automation_runner.arn
#         }
#       },
#     ]
#   })

# }#Rewrote the role below to not enforce jsonencode as we could write policy document

data "aws_iam_policy_document" "instance_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"

    principals {
      type        = "AWS"
      identifiers = [aws_iam_user.nhi_automation_runner.arn]
    }
  }
}

resource "aws_iam_role" "nhi_automation_runner_role" {
  name               = "nhi-automation-runner-role-${var.environment}"
  path               = "/"
  assume_role_policy = data.aws_iam_policy_document.instance_assume_role_policy.json
}

resource "aws_iam_role_policy_attachment" "nhi_automation_runner_role_attachment" {
  role       = aws_iam_role.nhi_automation_runner_role.name
  policy_arn = aws_iam_policy.role_policy.arn
}