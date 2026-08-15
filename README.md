```markdown
# NHI Risk Analyzer for AWS

An offline-first security automation platform that discovers, inventories, analyzes, risk-assesses, and safely remediates **Non-Human Identities (NHIs)** — IAM users, groups, roles, and associated policies — across AWS environments[cite: 1].

---

## 📋 Overview

**NHI Risk Analyzer** addresses a critical cloud security challenge: enterprise AWS environments accumulate hundreds of non-human identities (service accounts, automation roles, CI/CD credentials, cross-account roles) with minimal visibility into which identities are over-privileged, dormant, or introduce privilege-escalation risk[cite: 1].

The platform enforces strict architectural decoupling across three distinct phases:
1. **State Collection:** Live AWS ingestion into an `inventory.json` snapshot via Boto3[cite: 1].
2. **Offline Risk Evaluation:** Evaluating IAM security rules against the snapshot without live network dependencies[cite: 1]. This means the risk engine can be re-run, tested, and iterated on without touching AWS again, and every finding is reproducible against the exact account state it was generated from[cite: 1].
3. **Automated Remediation & Containment:** A fail-closed containment pipeline that neutralizes dangerous escalation attack paths via Permissions Boundaries and deactivates stale/dormant credentials without causing operational microservice outages.

---

## 🎯 Why This Project Exists

Enterprise AWS environments routinely contain non-human identities that are:

- **Unstandardized:** Created manually without consistent provisioning standards[cite: 1].
- **Over-Permissioned:** Granted administrative or wildcard permissions far exceeding actual operational needs[cite: 1].
- **Dormant & Forgotten:** Left active long after workloads or integration pipelines have been decommissioned[cite: 1].
- **Incompletely Audited:** Carrying inline policies that bypass standard managed-policy checks[cite: 1].
- **Credential Risks:** Utilizing access keys that are stale (>90 days old) or have never been used since inception[cite: 1].
- **Escalation-Prone:** Holding IAM permissions that, alone or combined, allow privilege escalation to full administrator access — documented attack paths that most policy-only scanners don't check for[cite: 1].

NHI Risk Analyzer automates discovery, security analysis, and targeted remediation using live AWS APIs and offline rule processing[cite: 1].

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
                                                        │   dispatch.py   │
                                                        │  (Remediation)  │
                                                        └────────┬────────┘
                                                                 │
                                       ┌─────────────────────────┴────────────────────────┐
                                       ▼                                                  ▼
                            ┌─────────────────────┐                            ┌─────────────────────┐
                            │      policy.py      │                            │    credential.py    │
                            │ (Attach Boundary)   │                            │ (Deactivate Key)    │
                            └─────────────────────┘                            └─────────────────────┘

```

1. **State Collection (`nhi/services/inventory.py`):** Queries AWS IAM APIs via Boto3, enriches user access key metadata with `GetAccessKeyLastUsed` details, and serializes a clean state snapshot to `inventory.json`.


2. **Offline Evaluation (`nhi/risk/risk.py`):** Loads `inventory.json` locally and passes resource payloads through modular security rules inside `nhi/risk/rules/`.


3. **Artifact Export (`nhi/services/export.py`):** Uploads `inventory.json` and security findings to an S3 bucket provisioned by Terraform.


4. **Remediation Dispatcher (`nhi/remediation/dispatch.py`):** Routes actionable findings through safe containment handlers with fail-closed safety, dry-run simulation mode, and exemption filtering via `nhi-ignore.yaml`.

---

## ⚡ Engineering Optimizations

### AWS Session Caching

To eliminate redundant AWS STS authentication calls during inventory collection, authenticated `boto3.Session` objects are cached for the lifetime of the Python process in `nhi/aws/session.py`.

* **STS `AssumeRole` calls reduced:** `35` → `1`

* **Inventory execution time reduced:** `79.58s` → `45.67s` (~**43% runtime improvement**)


* **Encapsulation:** Authentication remains fully encapsulated inside `session.py`, requiring zero logic changes to discovery or rule modules.



---

## 🛡️ Rule Coverage & Remediation Mapping

Rule IDs are grouped by category rather than numbered strictly sequentially — `IAM_01–03` cover general policy analysis, `IAM_04–08` cover documented privilege-escalation paths, and `IAM_11–12` cover credential hygiene. `IAM_09–10` are reserved for planned trust-policy analysis.

| Rule ID | Name | Category | Severity | Status | Remediation Action |
| --- | --- | --- | --- | --- | --- |
| **`IAM_01`** | Wildcard Actions in Policies

 | Policy Analysis

 | `HIGH`<br> | ✅ Implemented

 | Attach Permissions Boundary (`nhi-permissions-boundary`) |
| **`IAM_02`** | Wildcard Resources in Policies

 | Policy Analysis

 | `HIGH` / `LOW` (scoped-prefix downgrade)

 | ✅ Implemented

 | Attach Permissions Boundary (`nhi-permissions-boundary`) |
| **`IAM_03`** | Full Administrator Access

 | Policy Analysis

 | `CRITICAL`<br> | ✅ Implemented

 | Attach Permissions Boundary (Phase 5: Policy Detach) |
| **`IAM_04`** | Privilege Escalation via `iam:PassRole`<br> | Privilege Escalation

 | `HIGH`<br> | ✅ Implemented

 | Attach Permissions Boundary (Explicit Deny) |
| **`IAM_05`** | Privilege Escalation via `iam:CreatePolicyVersion`<br> | Privilege Escalation

 | `CRITICAL`<br> | ✅ Implemented

 | Attach Permissions Boundary (Explicit Deny) |
| **`IAM_06`** | Direct Escalation via Policy Attachment (`Attach*`/`Put*`)

 | Privilege Escalation

 | `CRITICAL`<br> | ✅ Implemented

 | Attach Permissions Boundary (Explicit Deny) |
| **`IAM_07`** | Privilege Escalation via `iam:CreateAccessKey`<br> | Privilege Escalation

 | `CRITICAL`<br> | ✅ Implemented

 | Attach Permissions Boundary (Explicit Deny) |
| **`IAM_08`** | Console Access Escalation (`Create`/`UpdateLoginProfile`)

 | Privilege Escalation

 | `CRITICAL`<br> | ✅ Implemented

 | Attach Permissions Boundary (Explicit Deny) |
| **`IAM_09`** | Permissive Role Trust Policies

 | Trust Analysis

 | `HIGH`<br> | 📋 Planned

 | Alert / Reporting Only |
| **`IAM_10`** | Unrestricted `sts:AssumeRole` Execution

 | Privilege Escalation

 | `HIGH` / `CRITICAL`<br> | 📋 Planned

 | Alert / Reporting Only |
| **`IAM_11`** | Stale Access Keys (>90 Days Old)

 | Credential Security

 | `HIGH` / `LOW`<br> | ✅ Implemented

 | Deactivate Key (`Status: Inactive`) |
| **`IAM_12`** | Unused & Dormant Access Keys (>30 Days)

 | Credential Security

 | `HIGH`<br> | ✅ Implemented

 | Deactivate Key (`Status: Inactive`) |

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

## 🔒 Containment Strategy: Why Permissions Boundaries?

Rather than performing destructive and risky surgical policy rewrites in real time (which can break legitimate production applications), automated policy remediation uses **Permissions Boundary Containment**:

* **Baseline Ceiling (`Allow *`):** Leaves routine operational read/write actions untouched so services do not crash.
* **Hard Deny Guardrails:** Explicitly denies dangerous escalation actions (`iam:PutUserPermissionsBoundary`, `iam:DeleteRolePermissionsBoundary`, `iam:PassRole`, `iam:CreatePolicyVersion`, etc.).
* **Non-Destructive Key Deactivation:** Stale and unused keys are toggled to `Inactive` rather than deleted, providing instant emergency rollback capabilities.
* **Exemption Management:** Protected identities (break-glass roles, runner identities) are defined in `nhi-ignore.yaml` and skipped automatically.

---

## 🗺️ Project Roadmap

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




* [x] **Phase 4: Automated Remediation Engine (Containment V1)**
* Permissions Boundary containment for privilege escalation and policy over-privilege (`nhi/remediation/handlers/policy.py`)
* Non-destructive access key deactivation (`nhi/remediation/handlers/credential.py`)
* Dispatch pipeline with `dry_run` simulation and `nhi-ignore.yaml` exemptions (`nhi/remediation/dispatch.py`)
* Terraform permissions boundary provisioning (`terraform/main.tf`)
* 100% offline unit test suite with `pytest` (`tests/test_remediation.py`)



---

### 🔮 Future Architectural Planning

#### Phase 5: Risk Engine V2 (Surgical Remediation)

* **Selective Policy Surgery:** Parse inline policy JSON documents and strip wildcard statements (`*`) down to scoped actions.
* **Direct AdministratorAccess Detachment:** Dedicated handler for `IAM_03` to remove root-equivalent managed policies directly.
* **IAM Group Edge-Case Handling:** Automated alerting and diff-reporting for group findings where boundaries cannot be attached.

#### Phase 6: Team Communication & Event Notifications

* **Slack & Microsoft Teams Webhooks:** High/Critical findings pushed to dedicated SecOps channels with interactive "Acknowledge" or "Remediate" buttons.


* **Jira / ITSM Ticket Automation:** Automatic ticket generation for identified high-severity policy wildcards or dormant keys, assigning tasks directly to resource owner teams.


* **Event-Driven Architecture (AWS EventBridge / Lambda):** Trigger scans automatically upon IAM creation events (`CreateUser`, `CreateAccessKey`, `PutRolePolicy`). At this point the automation runner's authentication moves off static keys entirely — GitHub Actions via OIDC federation for CI/CD triggers, and a Lambda execution role directly as the trust-policy principal.



---

## ⚙️ Environment & Execution Setup

> **⚠️ Local development note:** the setup below uses a static IAM access key for the runner identity, sourced via `admin.sh`/`runner.sh`. This is a **temporary, local-dev-only pattern** — the runner's own Terraform-managed IAM user only holds `sts:AssumeRole` permission (see `terraform/main.tf`), with all actual scan/export/remediation permissions living on the assumed role, not the user. The static key exists solely to bootstrap that first `AssumeRole` call during local development and is not intended to ship in any deployed or public-facing version of this project. Planned replacements: **AWS IAM Identity Center (SSO)** for local/human use, and **GitHub OIDC federation** for the CI/CD `nhi-action` (Phase 6) — both eliminate the static key entirely by authenticating the caller directly and issuing short-lived credentials.
> 
> 

The scanner relies on environment variables set up via shell scripts (`admin.sh` and `runner.sh`) to extract Terraform outputs and configure execution session credentials.

### 1. Admin Credentials Script (`admin.sh`)

Create `admin.sh` (not committed — add to `.gitignore`) to export initial administrator credentials required for Terraform operations:

```bash
export AWS_ACCESS_KEY_ID="<YOUR_ADMIN_ACCESS_KEY>"
export AWS_SECRET_ACCESS_KEY="<YOUR_ADMIN_SECRET_KEY>"

```

### 2. Runner Setup Script (`runner.sh`)

The project uses `runner.sh` to extract provisioned IAM runner credentials, assumed role ARN, permissions boundary ARN, and S3 bucket names from Terraform outputs:

```bash
CURRENT_DIR=$(pwd)

cd terraform || exit

NHI_ACCESS_KEY_ID=$(terraform output -raw nhi_automation_runner_access_key_id)
NHI_SECRET_ACCESS_KEY=$(terraform output -raw nhi_automation_runner_secret_access_key)
ROLE_ARN=$(terraform output -raw nhi_automation_runner_role_arn)
export ROLE_ARN="$ROLE_ARN"
export NHI_BOUNDARY_POLICY_ARN=$(terraform output -raw permissions_boundary_policy_arn)

export AWS_ACCESS_KEY_ID="$NHI_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$NHI_SECRET_ACCESS_KEY"

export ROLE_NAME=nhi-automation-runner-role-dev
export BUCKET_NAME=pam-infrastructure-automation-suite-dev-bucket

cd "$CURRENT_DIR"

```

---

## 🔐 Required IAM Permissions

The scanner execution role requires the following minimal IAM policy to inventory IAM resources, upload snapshots, and apply containment boundaries/key deactivations:

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
      "Sid": "IAMRemediationAccess",
      "Effect": "Allow",
      "Action": [
        "iam:PutUserPermissionsBoundary",
        "iam:PutRolePermissionsBoundary",
        "iam:UpdateAccessKey"
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
> 
> 

---

## 📂 Repository Structure

```text
nhi-risk-analyzer/
├── nhi/
│   ├── aws/                  # Boto3 wrappers & session management[cite: 1]
│   │   ├── iam.py            # IAM API helpers (get_access_key_last_used, set_*_boundary, update_key)[cite: 1]
│   │   ├── s3.py             # S3 upload utilities[cite: 1]
│   │   └── session.py        # Cached AWS session initialization[cite: 1]
│   ├── risk/
│   │   ├── risk.py           # Core risk engine runner[cite: 1]
│   │   └── rules/            # Modular evaluation rules[cite: 1]
│   │       ├── wildcards.py            # IAM_01, IAM_02, IAM_03[cite: 1]
│   │       ├── privilege_escalation.py # IAM_04–IAM_08 (Rhino-based escalation paths)[cite: 1]
│   │       └── credentials.py          # IAM_11, IAM_12[cite: 1]
│   ├── remediation/          # Automated remediation engine
│   │   ├── dispatch.py       # Handler routing & stats collection
│   │   ├── config.py         # Exemption parser (nhi-ignore.yaml)
│   │   └── handlers/
│   │       ├── policy.py     # Boundary attachment handler (IAM_01–IAM_08)
│   │       └── credential.py # Key deactivation handler (IAM_11–IAM_12)
│   ├── services/
│   │   ├── inventory.py      # State collection & key enrichment[cite: 1]
│   │   └── export.py         # Output export handlers[cite: 1]
│   └── config.py             # Global threshold configurations[cite: 1]
├── terraform/                 # Infrastructure as Code for runner & S3 bucket[cite: 1]
│   ├── main.tf                # Runner IAM user/role, S3 bucket, boundary policy[cite: 1]
│   ├── outputs.tf             # Terraform outputs
│   └── remote_state.tf        # Terraform state backend bucket[cite: 1]
├── tests/                     # Automated unit test suite[cite: 1]
│   ├── test_credentials.py    # Rule unit tests for IAM_11 / IAM_12[cite: 1]
│   ├── test_inventory.py      # Mock-injected inventory tests[cite: 1]
│   └── test_remediation.py    # Mock-injected remediation engine tests
├── nhi-ignore.yaml            # Exemption configuration file
├── admin.sh                   # Admin credentials bootstrap (gitignored)[cite: 1]
├── runner.sh                  # Dynamic runner credential export (gitignored)[cite: 1, 2]
└── README.md[cite: 1]

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
pip install boto3 pytest pyyaml

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
> 
> 
> ```hcl
> required_providers {
>   aws = {
>     source  = "hashicorp/aws"
>     version = "~> 6.0"
>   }
> }
> 
> ```
> 
> 
> then clear the local provider cache and lock file before reinitializing:
> 
> 
> ```bash
> rm -rf .terraform
> rm .terraform.lock.hcl
> terraform init
> 
> ```
> 
> 

**Verify the migration succeeded:**

```bash
terraform validate      # expect: Success! The configuration is valid.[cite: 1]
terraform plan           # expect: No changes. Your infrastructure matches the configuration.[cite: 1]
terraform state list      # confirms resources are enumerable from the remote backend[cite: 1]
terraform state pull      # confirms state is retrievable from the S3 backend[cite: 1]

```

Skip this whole bootstrap on subsequent clones/machines once the backend is already configured in the repo — `terraform init` alone will pull the existing remote state.

### 3. Provision Infrastructure via Terraform

```bash
source admin.sh
terraform apply -auto-approve
cd ..

```

### 4. Source Credentials & Execute Discovery / Risk Analysis

```bash
# Source dynamically generated runner credentials and boundary ARN[cite: 1, 2]
source runner.sh

# Run the complete discovery and risk analysis pipeline[cite: 1]
python -m nhi.risk.risk

```

---

## 🧪 Running Unit Tests

To run the full unit test suite offline without live AWS API dependencies:

```bash
python -m pytest -v tests/

```

```

```