# ==============================================================================
# CANARY TEST SUITE: NHI Risk Analyzer Validation
# ==============================================================================

locals {
  canary_tags = {
    Environment = "canary-test"
    Project     = "nhi-risk-analyzer"
  }
}

# ------------------------------------------------------------------------------
# 1. CANARY USER 1: Wildcards & AdministratorAccess (IAM_01, IAM_02, IAM_03)
# ------------------------------------------------------------------------------
resource "aws_iam_user" "canary_user_wildcards" {
  name          = "nhi-canary-user-wildcards"
  force_destroy = true
  tags          = local.canary_tags
}

resource "aws_iam_user_policy" "canary_inline_wildcards" {
  name = "canary-inline-wildcards"
  user = aws_iam_user.canary_user_wildcards.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "CanaryWildcardFinding"
        Effect   = "Allow"
        Action   = ["s3:*", "dynamodb:*"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_user_policy_attachment" "canary_admin_attach" {
  user       = aws_iam_user.canary_user_wildcards.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# ------------------------------------------------------------------------------
# 2. CANARY USER 2: Credential Hygiene (IAM_11, IAM_12)
# ------------------------------------------------------------------------------
resource "aws_iam_user" "canary_user_credentials" {
  name          = "nhi-canary-user-credentials"
  force_destroy = true
  tags          = local.canary_tags
}

resource "aws_iam_access_key" "canary_test_key" {
  user   = aws_iam_user.canary_user_credentials.name
  status = "Active"
}

# ------------------------------------------------------------------------------
# 3. CANARY ROLE 1: PassRole Escalation (IAM_04)
# ------------------------------------------------------------------------------
data "aws_caller_identity" "current" {}

resource "aws_iam_role" "canary_role_passrole" {
  name = "nhi-canary-role-passrole"
  tags = local.canary_tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "aws:PrincipalTag/CanaryAuthorized" = "true"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "canary_passrole_policy" {
  name = "canary-passrole-escalation"
  role = aws_iam_role.canary_role_passrole.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "PassRoleToEC2"
        Effect   = "Allow"
        Action   = ["iam:PassRole", "ec2:RunInstances"]
        Resource = "*"
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# 4. CANARY ROLE 2: Policy Versioning & Attachment Escalation (IAM_05, IAM_06)
# ------------------------------------------------------------------------------
resource "aws_iam_role" "canary_role_policy_escalation" {
  name = "nhi-canary-role-policy-escalation"
  tags = local.canary_tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "aws:PrincipalTag/CanaryAuthorized" = "true"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "canary_policy_escalation_policy" {
  name = "canary-policy-escalation"
  role = aws_iam_role.canary_role_policy_escalation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CreatePolicyVersionAndAttach"
        Effect = "Allow"
        Action = [
          "iam:CreatePolicyVersion",
          "iam:AttachRolePolicy",
          "iam:PutRolePolicy"
        ]
        Resource = "*"
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# 5. CANARY ROLE 3: Credential Escalation (IAM_07, IAM_08)
# ------------------------------------------------------------------------------
resource "aws_iam_role" "canary_role_cred_escalation" {
  name = "nhi-canary-role-cred-escalation"
  tags = local.canary_tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "aws:PrincipalTag/CanaryAuthorized" = "true"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "canary_cred_escalation_policy" {
  name = "canary-cred-escalation"
  role = aws_iam_role.canary_role_cred_escalation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CreateAccessKeyAndLoginProfile"
        Effect = "Allow"
        Action = [
          "iam:CreateAccessKey",
          "iam:CreateLoginProfile",
          "iam:UpdateLoginProfile"
        ]
        Resource = "*"
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# 6. CANARY ROLE 4: Set Default Policy Version Escalation (IAM_09)
# ------------------------------------------------------------------------------
resource "aws_iam_role" "canary_role_set_policy_version" {
  name = "nhi-canary-role-set-policy-version"
  tags = local.canary_tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "canary_set_policy_version_policy" {
  name = "canary-set-policy-version"
  role = aws_iam_role.canary_role_set_policy_version.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "SetDefaultVersionEscalation"
        Effect   = "Allow"
        Action   = ["iam:SetDefaultPolicyVersion"]
        Resource = "*"
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# 7. CANARY ROLE 5: Permissive Trust Policy (IAM_10)
# ------------------------------------------------------------------------------
resource "aws_iam_role" "nhi_canary_role_permissive_trust" {
  name        = "nhi-canary-role-permissive-trust"
  description = "Test canary for IAM_10: Public unconstrained sts:AssumeRole trust policy"
  tags        = local.canary_tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "sts:AssumeRole"
        Principal = {
          AWS = "*"
        }
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# 8. CANARY ROLE 6: Data Perimeter Exfiltration & Decryption (IAM_14, IAM_16)
# ------------------------------------------------------------------------------
resource "aws_iam_role" "canary_role_data_perimeter" {
  name = "nhi-canary-role-data-perimeter"
  tags = local.canary_tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "canary_data_perimeter_policy" {
  name = "canary-data-perimeter"
  role = aws_iam_role.canary_role_data_perimeter.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "S3DataExfiltration"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:GetObjectVersion"]
        Resource = "*"
      },
      {
        Sid      = "KMSDecryption"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = "*"
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# 9. CANARY ROLE 7: Security Defense Evasion (IAM_15)
# ------------------------------------------------------------------------------
resource "aws_iam_role" "canary_role_defense_evasion" {
  name = "nhi-canary-role-defense-evasion"
  tags = local.canary_tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "canary_defense_evasion_policy" {
  name = "canary-defense-evasion"
  role = aws_iam_role.canary_role_defense_evasion.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DefenseEvasionActions"
        Effect = "Allow"
        Action = [
          "cloudtrail:StopLogging",
          "cloudtrail:DeleteTrail",
          "guardduty:DeleteDetector",
          "kms:DisableKey"
        ]
        Resource = "*"
      }
    ]
  })
}