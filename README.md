# NHI Risk Analyzer for AWS

An offline-first security automation platform that discovers, inventories, analyzes, and risk-assesses **Non-Human Identities (NHIs)** — IAM users, groups, roles, and associated policies — across AWS environments.

---

## 📋 Overview

**NHI Risk Analyzer** addresses a critical cloud security challenge: enterprise AWS environments accumulate hundreds of non-human identities (service accounts, automation roles, CI/CD credentials, cross-account roles) with minimal visibility into which identities are over-privileged, dormant, or introduce privilege-escalation risk.

The platform enforces strict architectural decoupling between **State Collection** (live AWS ingestion into an `inventory.json` snapshot) and **Offline Risk Evaluation** (evaluating IAM security rules against the snapshot without live network dependencies). This means the risk engine can be re-run, tested, and iterated on without touching AWS again, and every finding is reproducible against the exact account state it was generated from.

---

## 🎯 Why This Project Exists

Enterprise AWS environments routinely contain non-human identities that are:

- **Unstandardized:** Created manually without consistent provisioning standards.
- **Over-Permissioned:** Granted administrative or wildcard permissions far exceeding actual operational needs.
- **Dormant & Forgotten:** Left active long after workloads or integration pipelines have been decommissioned.
- **Incompletely Audited:** Carrying inline policies that bypass standard managed-policy checks.
- **Credential Risks:** Utilizing access keys that are stale (>90 days old) or have never been used since inception.
- **Escalation-Prone:** Holding IAM permissions that, alone or combined, allow privilege escalation to full administrator access — documented attack paths that most policy-only scanners don't check for.

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

Rule IDs are grouped by category rather than numbered strictly sequentially — `IAM_01–03` cover general policy analysis, `IAM_04–08` cover documented privilege-escalation paths, and `IAM_11–12` cover credential hygiene. `IAM_09–10` are reserved for planned trust-policy analysis.

| Rule ID | Name | Category | Severity | Status |
| --- | --- | --- | --- | --- |
| **`IAM_01`** | Wildcard Actions in Policies | Policy Analysis | `HIGH` | ✅ Implemented |
| **`IAM_02`** | Wildcard Resources in Policies | Policy Analysis | `HIGH` / `LOW` (scoped-prefix downgrade) | ✅ Implemented |
| **`IAM_03`** | Full Administrator Access | Policy Analysis | `CRITICAL` | ✅ Implemented |
| **`IAM_04`** | Privilege Escalation via `iam:PassRole` | Privilege Escalation | `HIGH` | ✅ Implemented |
| **`IAM_05`** | Privilege Escalation via `iam:CreatePolicyVersion` | Privilege Escalation | `CRITICAL` | ✅ Implemented |
| **`IAM_06`** | Direct Escalation via Policy Attachment (`Attach*`/`Put*`) | Privilege Escalation | `CRITICAL` | ✅ Implemented |
| **`IAM_07`** | Privilege Escalation via `iam:CreateAccessKey` | Privilege Escalation | `CRITICAL` | ✅ Implemented |
| **`IAM_08`** | Console Access Escalation (`Create`/`UpdateLoginProfile`) | Privilege Escalation | `CRITICAL` | ✅ Implemented |
| **`IAM_09`** | Permissive Role Trust Policies | Trust Analysis | `HIGH` | 📋 Planned |
| **`IAM_10`** | Unrestricted `sts:AssumeRole` Execution | Privilege Escalation | `HIGH` / `CRITICAL` | 📋 Planned |
| **`IAM_11`** | Stale Access Keys (>90 Days Old) | Credential Security | `HIGH` / `LOW` | ✅ Implemented |
| **`IAM_12`** | Unused & Dormant Access Keys (>30 Days) | Credential Security | `HIGH` | ✅ Implemented |

**Detection methodology sources:** Rules are informed by Rhino Security Labs' documented AWS IAM privilege escalation research (21 methods), Salesforce's Cloudsplaining policy-severity methodology, the CIS AWS Foundations Benchmark (credential hygiene thresholds), and AWS's own IAM best-practices documentation.

### Example Security Finding

```json
{
  "RuleID": "IAM_03",
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
  * Modular security rules (`wildcards.py`, `credentials.py`, `privilege_escalation.py`)
  * Detection for wildcard actions/resources, admin access, stale keys, unused/dormant keys, and documented IAM privilege-escalation paths
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
  * At this point the automation runner's authentication also moves off static keys entirely — GitHub Actions via OIDC federation for CI/CD triggers, and a Lambda execution role directly as the trust-policy principal for event-driven triggers.

---

## ⚙️ Environment & Execution Setup

> **⚠️ Local development note:** the setup below uses a static IAM access key for the runner identity, sourced via `admin.sh`/`runner.sh`. This is a **temporary, local-dev-only pattern** — the runner's own Terraform-managed IAM user only holds `sts:AssumeRole` permission (see `terraform/main.tf`), with all actual scan/export permissions living on the assumed role, not the user. The static key exists solely to bootstrap that first `AssumeRole` call during local development and is not intended to ship in any deployed or public-facing version of this project. Planned replacements: **AWS IAM Identity Center (SSO)** for local/human use, and **GitHub OIDC federation** for the CI/CD `nhi-action` (Phase 5) — both eliminate the static key entirely by authenticating the caller directly and issuing short-lived credentials.

The scanner relies on environment variables set up via shell scripts (`admin.sh` and `runner.sh`) to extract Terraform outputs and configure execution session credentials.

### 1. Admin Credentials Script (`admin.sh`)

Create `admin.sh` (not committed — add to `.gitignore`) to export initial administrator credentials required for Terraform operations:

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

> **Note:** most of the `iam:List*`/`iam:Get*` actions above can be consolidated into a single `iam:GetAccountAuthorizationDetails` call, which returns users, groups, roles, and all attached/inline policy documents in one response. `ListAccessKeys` and `GetAccessKeyLastUsed` are not covered by that call and stay separate. This consolidation is a planned simplification, tracked for a future update — the granular list above reflects the current `terraform/main.tf`.

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
│   │       ├── wildcards.py            # IAM_01, IAM_02, IAM_03
│   │       ├── privilege_escalation.py # IAM_04–IAM_08 (Rhino-based escalation paths)
│   │       └── credentials.py          # IAM_11, IAM_12
│   ├── services/
│   │   ├── inventory.py      # State collection & key enrichment
│   │   └── export.py         # Output export handlers
│   └── config.py             # Global threshold configurations
├── terraform/                 # Infrastructure as Code for runner & S3 bucket
│   ├── main.tf                # Runner IAM user/role, S3 bucket, policies
│   └── remote_state.tf        # Terraform state backend bucket (see Quick Start bootstrap note)
├── tests/                     # Automated unit test suite
│   ├── test_credentials.py    # Rule unit tests for IAM_11 / IAM_12
│   └── test_inventory.py      # Mock-injected inventory tests
├── automation_test.py         # End-to-end integration test runner
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
git clone https://github.com/likithmanoj/nhi-risk-analyzer.git
cd nhi-risk-analyzer

python3 -m venv .venv
source .venv/bin/activate
pip install boto3 pytest
```

### 2. Bootstrap the Remote State Backend (first-time setup only)

The S3 bucket that stores Terraform's remote state is itself a Terraform-managed resource (`terraform/remote_state.tf`), which means it can't be its own backend on the very first apply. This was solved in two passes:

**Pass 1 — create the backend bucket while still using local state:**

```bash
cd terraform
terraform init
terraform apply
```

At this stage `remote_state.tf`'s resources (bucket, versioning, encryption, public access block) are created, and Terraform is still tracking state locally (`terraform.tfstate` in the working directory) — the backend configuration hasn't been added to the config yet.

**Pass 2 — add the backend block and migrate:**

Once the bucket exists, add the `backend "s3" {...}` block (pointing at the bucket from Pass 1) to your Terraform configuration, then re-initialize:

```bash
terraform init
```

Terraform detects the existing local state file and prompts:

```
Do you want to copy existing state to the new backend?
```

Answering `yes` copies the local `terraform.tfstate` into the S3 backend. From this point on, Terraform reads and writes remote state instead of the local file.

> **Provider version conflict during migration:** if the remote state was created with a newer AWS provider version than your local config is constrained to (e.g. state written with provider `6.x`, local config pinned to `~> 5.0`), migration can fail with `Resource instance managed by newer provider version` — the older provider can't decode state written by a newer provider's schema. Fix by updating `required_providers` to match the newer version:
> ```hcl
> required_providers {
>   aws = {
>     source  = "hashicorp/aws"
>     version = "~> 6.0"
>   }
> }
> ```
> then clear the local provider cache and lock file before reinitializing:
> ```bash
> rm -rf .terraform
> rm .terraform.lock.hcl
> terraform init
> ```

**Verify the migration succeeded:**

```bash
terraform validate      # expect: Success! The configuration is valid.
terraform plan           # expect: No changes. Your infrastructure matches the configuration.
terraform state list      # confirms resources are enumerable from the remote backend
terraform state pull      # confirms state is retrievable from the S3 backend
```

Skip this whole bootstrap on subsequent clones/machines once the backend is already configured in the repo — `terraform init` alone will pull the existing remote state.

### 3. Provision the Remaining Infrastructure

```bash
terraform apply -auto-approve
cd ..
```

### 4. Source Credentials & Execute Scanner

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