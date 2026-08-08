```markdown
# NHI Risk Analyzer for AWS

An offline-first security automation platform that discovers, inventories, analyzes, and risk-assesses **Non-Human Identities (NHIs)** — IAM users, groups, roles, and associated policies — across AWS environments.

---

## 📋 Overview

**NHI Risk Analyzer** addresses a critical cloud security challenge: enterprise AWS environments accumulate hundreds of non-human identities (service accounts, automation roles, CI/CD credentials, cross-account roles) with minimal visibility into which identities are over-privileged, dormant, or introduce privilege-escalation risk.

The platform enforces strict architectural decoupling between **State Collection** (live AWS ingestion into an `inventory.json` snapshot) and **Offline Risk Evaluation** (evaluating IAM security rules against the snapshot without live network dependencies).

---

## 🎯 Why This Project Exists

Enterprise AWS environments routinely contain non-human identities that are:

- **Unstandardized:** Created manually without consistent provisioning standards.
- **Over-Permissioned:** Granted administrative or wildcard permissions far exceeding actual operational needs.
- **Dormant & Forgotten:** Left active long after workloads or integration pipelines have been decommissioned.
- **Incompletely Audited:** Carrying inline policies that bypass standard managed-policy checks.
- **Credential Risks:** Utilizing access keys that are stale (>90 days old) or have never been used since inception.

NHI Risk Analyzer automates discovery and security analysis using live AWS APIs and offline rule processing.

---

## 🏗️ Architecture & Workflow

```text
  ┌──────────────┐         ┌──────────────────┐         ┌─────────────────┐
  │   AWS IAM    │ ──────> │   inventory.py   │ ──────> │  inventory.json │
  │   APIs       │  boto3  │ (State Collector)│         │   (Raw Snapshot)│
  └──────────────┘         └──────────────────┘         └────────┬────────┘
                                                                 │
                                                                 ▼
  ┌──────────────┐         ┌──────────────────┐         ┌─────────────────┐
  │  S3 Snapshot │ <────── │      export.py   │ <────── │     risk.py     │
  │   Storage    │  upload │   (S3 Export)    │         │ (Offline Engine)│
  └──────────────┘         └──────────────────┘         └────────┬────────┘
                                                                 │
                                                                 ▼
                                                        ┌─────────────────┐
                                                        │ Future Engine:  │
                                                        │ Remediation &   │
                                                        │ Team Alerts     │
                                                        └─────────────────┘

```

1. **State Collection (`nhi/services/inventory.py`):** Queries AWS IAM APIs via Boto3, enriches user access key metadata with `GetAccessKeyLastUsed` details, and serializes a clean state snapshot to `inventory.json`.
2. **Offline Evaluation (`nhi/risk/risk.py`):** Loads `inventory.json` locally and passes resource payloads through modular security rules inside `nhi/risk/rules/`.
3. **Artifact Export (`nhi/services/export.py`):** Uploads `inventory.json` and security findings to an S3 bucket provisioned by Terraform.

---

## ⚡ Engineering Optimizations

### AWS Session Caching

To eliminate redundant AWS STS authentication calls during inventory collection, authenticated `boto3.Session` objects are cached for the lifetime of the Python process in `nhi/aws/session.py`.

* **STS `AssumeRole` calls reduced:** `35` → `1`
* **Inventory execution time reduced:** `79.58s` → `45.67s` (~**43% runtime improvement**)
* **Encapsulation:** Authentication remains fully encapsulated inside `session.py`, requiring zero logic changes to discovery or rule modules.

---

## 🛡️ Rule Coverage Status

| Rule ID | Name | Category | Severity | Status |
| --- | --- | --- | --- | --- |
| **`IAM_01`** | Wildcard Actions in Policies | Policy Analysis | `HIGH` | ✅ Implemented |
| **`IAM_02`** | Wildcard Resources in Policies | Policy Analysis | `HIGH` | ✅ Implemented |
| **`IAM_03`** | Full Administrator Access | Policy Analysis | `CRITICAL` | ✅ Implemented |
| **`IAM_04`** | Privilege Escalation via `iam:PassRole` | Privilege Escalation | `HIGH` | ✅ Implemented |
| **`IAM_05`** | Privilege Escalation via `iam:CreatePolicyVersion` | Privilege Escalation | `CRITICAL` | ✅ Implemented |
| **`IAM_06`** | Direct Escalation via Policy Attachment (`Attach*`/`Put*`) | Privilege Escalation | `CRITICAL` | ✅ Implemented |
| **`IAM_07`** | Privilege Escalation via `iam:CreateAccessKey` | Privilege Escalation | `CRITICAL` | ✅ Implemented |
| **`IAM_08`** | Console Access Escalation (`Create`/`UpdateLoginProfile`) | Privilege Escalation | `CRITICAL` | ✅ Implemented |
| **`IAM_09`** | Permissive Role Trust Policies | Trust Analysis | `HIGH` | 📋 Planned |
| **`IAM_10`** | Unrestricted `sts:AssumeRole` Execution | Privilege Escalation | `HIGH` / `CRITICAL` | 📋 Planned |

### Example Security Finding

```json
{
  "IdentityType": "User",
  "IdentityName": "pam-suite-admin",
  "PolicyName": "IAMFullAccess",
  "Action": "iam:*",
  "Finding": "Administrator-Equivalent Permissions",
  "Resource": "*",
  "Severity": "CRITICAL"
}

```

---

## 🗺️ Project Roadmap & Future Planning

### Completed Milestones

* [x] **Phase 1: AWS Infrastructure Foundation**
* Infrastructure as Code via Terraform (`terraform/`)
* Least-privilege IAM architecture and assume-role execution
* Secure remote S3 state backend with encryption & versioning


* [x] **Phase 2: Discovery Engine & Ingestion**
* IAM Users, Groups, Roles, Managed Policies & Inline Policies discovery
* Access Key metadata enrichment (`GetAccessKeyLastUsed`)
* Session caching for Boto3 API pagination
* Snapshot export to local `inventory.json` and remote S3


* [x] **Phase 3: Risk Evaluation Engine**
* Modular security rules (`wildcards.py`, `credentials.py`)
* Detection for wildcard actions/resources, admin access, stale keys, and unused/dormant keys
* Unit testing suite with `@patch` mock injection (`tests/`)



---

### 🔮 Future Architectural Planning

#### Phase 4: Production-Safe Automated Remediation Engine

The primary engineering objective for remediation is **zero production downtime**. Automated policy changes will follow a safe, gradual rollback workflow:

* **Dry-Run & Impact Simulation:**
* Evaluate proposed policy reductions against historical AWS CloudTrail activity before applying changes.
* Generate a "Diff Preview" showing exact permissions to be detached or replaced.


* **Non-Destructive Deactivation (Safe Remediation):**
* **Access Key Inactivation:** Automatically set unused/dormant keys to `Inactive` rather than deleting them, preserving quick emergency rollback options.
* **Inline Policy Detachment / Backup:** Store exact policy versions in S3 prior to stripping wildcard permissions.


* **Automated Rollback Mechanism:**
* One-click restore workflows to re-enable keys or re-attach original policies if service degradation is detected.


* **Production Guardrails:**
* Whitelisting engine (`nhi-ignore.yaml`) to protect core infrastructure roles (e.g., break-glass roles, deployment pipelines) from automated remediation actions.



#### Phase 5: Team Communication & Event Notifications

To bridge security findings with DevOps workflows, the platform will integrate real-time notifications and ticketing pipelines:

* **Slack & Microsoft Teams Webhooks:**
* High and Critical findings pushed to dedicated SecOps channels with interactive "Acknowledge" or "Remediate" buttons.
* Daily digest summaries detailing new, resolved, and stale security risks.


* **Jira / ITSM Integration:**
* Automatic ticket generation for identified high-severity policy wildcards or dormant keys, assigning tasks directly to resource owner teams.


* **Event-Driven Architecture (AWS EventBridge / Lambda):**
* Trigger scans automatically upon IAM creation events (`CreateUser`, `CreateAccessKey`, `PutRolePolicy`).



---

## ⚙️ Environment & Execution Setup

The scanner relies on environment variables set up via shell scripts (`admin.sh` and `runner.sh`) to extract Terraform outputs and configure execution session credentials.

### 1. Admin Credentials Script (`admin.sh`)

Create `admin.sh` to export initial administrator credentials required for Terraform operations:

```bash
export AWS_ACCESS_KEY_ID="<YOUR_ADMIN_ACCESS_KEY>"
export AWS_SECRET_ACCESS_KEY="<YOUR_ADMIN_SECRET_KEY>"

```

### 2. Runner Setup Script (`runner.sh`)

The project uses `runner.sh` to extract provisioned IAM runner credentials and S3 bucket names from Terraform outputs:

```bash
CURRENT_DIR=$(pwd)

# Navigate to terraform directory to fetch outputs
cd terraform || exit

NHI_ACCESS_KEY_ID=$(terraform output -raw nhi_automation_runner_access_key_id)
NHI_SECRET_ACCESS_KEY=$(terraform output -raw nhi_automation_runner_secret_access_key)
ROLE_ARN=$(terraform output -raw nhi_automation_runner_role_arn)

export ROLE_ARN="$ROLE_ARN"
export AWS_ACCESS_KEY_ID="$NHI_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$NHI_SECRET_ACCESS_KEY"

export ROLE_NAME="nhi-automation-runner-role-dev"
export BUCKET_NAME="pam-infrastructure-automation-suite-dev-bucket"

# Return to project root directory
cd "$CURRENT_DIR"

```

---

## 🔐 Required IAM Permissions

The scanner execution role requires the following minimal IAM policy to inventory IAM resources and upload snapshots:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "IAMInventoryReadAccess",
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers",
        "iam:ListRoles",
        "iam:ListGroups",
        "iam:ListPolicies",
        "iam:ListAttachedUserPolicies",
        "iam:ListAttachedRolePolicies",
        "iam:ListAttachedGroupPolicies",
        "iam:ListUserPolicies",
        "iam:ListRolePolicies",
        "iam:ListGroupPolicies",
        "iam:GetUserPolicy",
        "iam:GetRolePolicy",
        "iam:GetGroupPolicy",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:GetRole",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed"
      ],
      "Resource": "*"
    },
    {
      "Sid": "S3InventoryExportAccess",
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject"
      ],
      "Resource": "arn:aws:s3:::pam-infrastructure-automation-suite-dev-bucket/*"
    }
  ]
}

```

---

## 📂 Repository Structure

```text
nhi-risk-analyzer/
├── nhi/
│   ├── aws/                  # Boto3 wrappers & session management
│   │   ├── iam.py            # IAM API helpers (get_access_key_last_used)
│   │   ├── s3.py             # S3 upload utilities
│   │   └── session.py        # Cached AWS session initialization
│   ├── risk/
│   │   ├── risk.py           # Core risk engine runner
│   │   └── rules/            # Modular evaluation rules
│   │       ├── credentials.py# IAM_07 & IAM_08 evaluation logic
│   │       └── wildcards.py  # IAM_01, IAM_02 & IAM_03 evaluation logic
│   ├── services/
│   │   ├── inventory.py      # State collection & key enrichment
│   │   └── export.py         # Output export handlers
│   └── config.py             # Global threshold configurations
├── terraform/                # Infrastructure as Code for runner & S3 bucket
├── tests/                    # Automated unit test suite
│   ├── test_credentials.py   # Rule unit tests for IAM_08
│   └── test_inventory.py     # Mock-injected inventory tests
├── automation_test.py        # End-to-end integration test runner
└── README.md

```

---

## 🚀 Quick Start Guide

### Prerequisites

* Python 3.10+
* Terraform 1.5+
* AWS CLI configured

### 1. Clone & Setup Virtual Environment

```bash
git clone [https://github.com/likithmanoj/nhi-risk-analyzer.git](https://github.com/likithmanoj/nhi-risk-analyzer.git)
cd nhi-risk-analyzer

python3 -m venv .venv
source .venv/bin/activate
pip install boto3 pytest

```

### 2. Provision Infrastructure (Terraform)

```bash
cd terraform
terraform init
terraform apply -auto-approve
cd ..

```

### 3. Source Credentials & Execute Scanner

```bash
# Source administrative and runner environment variables
source admin.sh
source runner.sh

# Run the complete discovery and risk analysis pipeline
python -m nhi.risk.risk

```

---

## 🧪 Running Unit Tests

To run the unit test suite offline using mock injection (no live AWS API calls required):

```bash
python3 -m unittest discover -s tests

```

```

```