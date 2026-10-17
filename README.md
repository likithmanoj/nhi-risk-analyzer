# Multi-Cloud Non-Human Identity (NHI) Risk Analyzer & Remediator

An enterprise-grade, offline-first security automation platform that discovers, inventories, analyzes, risk-assesses, and safely remediates **Non-Human Identities (NHIs)** — service principals, service accounts, machine roles, access keys, and credentials — across **AWS, Azure, and Google Cloud Platform (GCP)**.

> ⭐️ **If you find this tool helpful for auditing and securing Non-Human Identities across clouds, please consider starring the repository!**

---

## 🌐 Multi-Cloud Identity Coverage

| Cloud Provider | Identity Types Covered | Discovery Engine | Secret / Credential Inspection | Rules Active | Status |
|:---|:---|:---|:---|:---|:---|
| 🟧 **AWS** | IAM Roles, Machine Users, Groups, Policies | Boto3 + Session Caching | Access Keys (`CreateDate`, `LastUsed`) | 13 Rules (`AWS_01`–`16`, `TAG_01`) | ✅ Supported |
| 🟦 **Azure** | Entra ID Service Principals, App Registrations, Managed Identities | Pure REST (Graph & ARM) | Client Secrets (`passwordCredentials`), Certs (`keyCredentials`) | 5 Rules (`AZURE_01`–`05`) | ✅ Supported |
| 🟥 **GCP** | Service Accounts, Workload Identity, IAM Roles | Pure REST (IAM & Resource Mgr) | Service Account Keys (`validAfterTime`, user-managed) | 6 Rules (`GCP_01`–`06`) | ✅ Supported |

> 🧪 **Test Suite Status:** **102 passed, 4 subtests passed (100% GREEN)** across all providers and engines.

---

## 📋 Overview

**NHI Risk Analyzer** addresses a critical multi-cloud security challenge: modern enterprise cloud environments accumulate hundreds of machine and non-human identities (service accounts, automation roles, CI/CD credentials, cross-cloud trust roles) with minimal visibility into which identities are over-privileged, dormant, or introduce privilege-escalation risk.

The platform enforces strict architectural decoupling across three distinct phases:

1. **Multi-Cloud State Collection:** Ingestion into a normalized `inventory.json` snapshot via lightweight, cloud-native mechanisms (Boto3 session-cached for AWS; zero-dependency pure REST for Azure and GCP).
2. **Offline Risk Evaluation:** Evaluating security rules against the snapshot without live network dependencies. This means the risk engine can be re-run, tested, and iterated on without touching cloud providers again, and every finding is reproducible against the exact account/tenant state it was generated from.
3. **Automated Remediation & Containment:** A fail-closed containment pipeline that neutralizes dangerous escalation attack paths via policy boundaries and deactivates stale/dormant credentials without causing operational microservice outages.

---

## 🎯 Why This Project Exists

Enterprise multi-cloud environments routinely contain non-human identities that are:

- **Unstandardized:** Created manually across disparate clouds without unified provisioning standards.
- **Over-Permissioned:** Granted administrative or wildcard permissions far exceeding actual operational needs.
- **Dormant & Forgotten:** Left active long after workloads or integration pipelines have been decommissioned.
- **Incompletely Audited:** Carrying inline policies, custom role definitions, or direct bindings that bypass standard compliance checks.
- **Credential Risks:** Utilizing access keys, client secrets, or service account keys that are stale (>90 days old), expiring, or have never been used since inception.
- **Escalation-Prone:** Holding cloud IAM permissions that, alone or combined, allow privilege escalation to full administrator access — documented attack paths that most policy-only scanners don't check for.

NHI Risk Analyzer automates discovery, security analysis, and targeted remediation across cloud providers using cloud APIs and offline rule processing.

---

## 🏗️ Architecture & Workflow

```text
  ┌──────────────┐         ┌──────────────┐         ┌──────────────┐
  │   AWS IAM    │         │  Azure Entra │         │   GCP IAM    │
  │   (Boto3)    │         │  (Pure REST) │         │  (Pure REST) │
  └──────┬───────┘         └──────┬───────┘         └──────┬───────┘
         │                        │                        │
         └────────────────┐       │       ┌────────────────┘
                          ▼       ▼       ▼
                    ┌───────────────────────────┐
                    │       inventory.py        │
                    │ (Multi-Cloud Collector)   │
                    └─────────────┬─────────────┘
                                  ▼
                    ┌───────────────────────────┐
                    │      inventory.json       │
                    │  (Unified State Snapshot) │
                    └─────────────┬─────────────┘
                                  │
                                  ▼
                    ┌───────────────────────────┐
                    │          risk.py          │
                    │    (--cloud Orchestrator) │
                    └─────────────┬─────────────┘
                                  │
         ┌────────────────────────┼────────────────────────┐
         ▼                        ▼                        ▼
  ┌──────────────┐         ┌──────────────┐         ┌──────────────┐
  │  aws.py sub- │         │ azure.py sub-│         │  gcp.py sub- │
  │    runner    │         │    runner    │         │    runner    │
  │ (13 Rules)   │         │  (5 Rules)   │         │  (6 Rules)   │
  └──────┬───────┘         └──────┬───────┘         └──────┬───────┘
         └────────────────────────┼────────────────────────┘
                                  ▼
                    ┌───────────────────────────┐
                    │        dispatch.py        │
                    │ (Containment Dispatcher)  │
                    └─────────────┬─────────────┘
                                  │
         ┌────────────────────────┴────────────────────────┐
         ▼                                                 ▼
┌─────────────────────────┐                     ┌─────────────────────┐
│ policy_surgery.py &     │                     │    credential.py    │
│ policy.py (Boundaries)  │                     │ (Deactivate Key)    │
└─────────────────────────┘                     └─────────────────────┘
```

1. **State Collection (`nhi/services/inventory.py`):** Queries cloud APIs across AWS, Azure, and GCP, enriches credential metadata (access key last-used, secret expiration), and serializes a clean state snapshot to `inventory.json`.
2. **Selective Cloud Orchestrator (`nhi/risk/risk.py`):** Accepts `--cloud {aws,azure,gcp,all}` to selectively target cloud providers, saving unnecessary API calls and avoiding cross-tenant rate limits.
3. **Modular Risk Runners (`nhi/risk/runners/`):** Decoupled execution engines (`aws.py`, `azure.py`, `gcp.py`) process provider inventories against modular security rules with defensive guards against partial or missing cloud payloads.
4. **Artifact Export & Run-over-Run Diffing (`nhi/services/export.py`, `nhi/remediation/diff.py`):** Calculates security drift against historical baseline scans, uploads execution artifacts to cloud storage, and exports findings to CSV and OASIS SARIF v2.1.0 for audit pipelines.
5. **Remediation & Policy Surgery (`nhi/remediation/`):** AST-level policy statement partitioning (`policy_surgery.py`) and non-destructive containment boundaries/key deactivation with dry-run simulation mode and `nhi-ignore.yaml` exemptions.

---


## ⚡ Engineering Optimizations

### AWS Session Caching

To eliminate redundant AWS STS authentication calls during inventory collection, authenticated `boto3.Session` objects are cached for the lifetime of the Python process in `nhi/aws/session.py`.

- **STS `AssumeRole` calls reduced:** `35` → `1`
- **Inventory execution time reduced:** `79.58s` → `45.67s` (~**43% runtime improvement**)
- **Encapsulation:** Authentication remains fully encapsulated inside `session.py`, requiring zero logic changes to discovery or rule modules.

### Pure REST Multi-Cloud Discovery (Azure & GCP)

Rather than bundling heavy, fragmented cloud SDKs (`azure-mgmt-*`, `msgraph-sdk`, `google-cloud-iam` + `grpcio`), the multi-cloud discovery layer utilizes a unified, lightweight **pure HTTP (`requests`) + Bearer token** design:

- **Container Footprint:** Reduces container image size from >300MB to <50MB by eliminating native compiled C/C++ libraries (`grpcio`).
- **Serverless Cost Optimization:** Drops memory footprint significantly, enabling execution within the lowest container RAM tiers (128MB / 256MB) and slashing cold-start latencies.
- **Dual-Plane Ingestion:**
  - **Identity Plane (Microsoft Graph):** Direct queries to `https://graph.microsoft.com/v1.0` for Entra ID Users, Security Groups, Service Principals, and App Registrations.
  - **Resource Plane (ARM):** Queries to `https://management.azure.com` for Role Assignments, Role Definitions, and User-Assigned Managed Identities.

---

## 🛡️ Rule Coverage & Remediation Mapping

The platform enforces **26 active security rules** across AWS, Azure, and GCP, targeting privilege escalation vectors, overly permissive policies, and dormant machine credentials.

### 🟧 AWS IAM Rules

| Rule ID | Name | Category | Severity | Status | Remediation / Impact |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`AWS_01`** | Wildcard Actions in Policies | Policy Analysis | `HIGH` | ✅ Implemented | Attach Permissions Boundary (`nhi-permissions-boundary`) |
| **`AWS_02`** | Wildcard Resources in Policies | Policy Analysis | `HIGH` / `LOW` | ✅ Implemented | Attach Permissions Boundary / AST Statement Partitioning |
| **`AWS_03`** | Full Administrator Access | Policy Analysis | `CRITICAL` | ✅ Implemented | Attach Permissions Boundary (detach planned for Phase 5) |
| **`AWS_04`** | Privilege Escalation via `iam:PassRole` | Privilege Escalation | `HIGH` | ✅ Implemented | Attach Permissions Boundary (Explicit Deny) |
| **`AWS_05`** | Privilege Escalation via `iam:CreatePolicyVersion` | Privilege Escalation | `CRITICAL` | ✅ Implemented | Attach Permissions Boundary (Explicit Deny) |
| **`AWS_06`** | Direct Escalation via Policy Attachment (`Attach*`/`Put*`) | Privilege Escalation | `CRITICAL` | ✅ Implemented | Attach Permissions Boundary (Explicit Deny) |
| **`AWS_07`** | Privilege Escalation via `iam:CreateAccessKey` | Privilege Escalation | `CRITICAL` | ✅ Implemented | Attach Permissions Boundary (Explicit Deny) |
| **`AWS_08`** | Console Access Escalation (`Create`/`UpdateLoginProfile`) | Privilege Escalation | `CRITICAL` | ✅ Implemented | Attach Permissions Boundary (Explicit Deny) |
| **`AWS_09`** | Privilege Escalation via `iam:SetDefaultPolicyVersion` | Privilege Escalation | `CRITICAL` | ✅ Implemented | Attach Permissions Boundary (Explicit Deny) |
| **`AWS_10`** | Permissive Role Trust Policies (`*` AssumeRole Principal) | Trust Policy Analysis | `CRITICAL` | ✅ Implemented | Attach Permissions Boundary (`nhi-permissions-boundary`) |
| **`AWS_11`** | Stale Access Keys (>90 Days Old) | Credential Security | `HIGH` / `LOW` | ✅ Implemented | Deactivate Key (`Status: Inactive`) |
| **`AWS_12`** | Unused & Dormant Access Keys (>30 Days) | Credential Security | `HIGH` | ✅ Implemented | Deactivate Key (`Status: Inactive`) |
| **`AWS_14`** | Unrestricted S3 Data Exfiltration (`s3:GetObject*`, `s3:*`) | Data Perimeter | `HIGH` | ✅ Implemented | Attach Permissions Boundary (`nhi-permissions-boundary`) |
| **`AWS_15`** | Security Defense Evasion (CloudTrail/GuardDuty/KMS tampering) | Resource Protection | `CRITICAL` | ✅ Implemented | Attach Permissions Boundary (`nhi-permissions-boundary`) |
| **`AWS_16`** | Unrestricted KMS Decryption (`kms:Decrypt`, `kms:*`) | Data Perimeter | `HIGH` | ✅ Implemented | Attach Permissions Boundary (`nhi-permissions-boundary`) |
| **`TAG_01`** | Missing Mandatory Governance Tags (`Owner`, `Environment`) | Governance & Tagging | `LOW` | ✅ Implemented | Apply Mandatory Tags |

### 🟦 Azure Entra ID & RBAC Rules

| Rule ID | Name | Category | Severity | Status | Attack Vector / Detection |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`AZURE_01`** | Subscription Takeover via Owner / User Access Admin | Privilege Escalation | `CRITICAL` | ✅ Implemented | Service Principal assigned `Owner` or `User Access Administrator` at subscription scope (`/subscriptions/{id}`) |
| **`AZURE_02`** | Entra ID Privilege Escalation via Microsoft Graph | Privilege Escalation | `CRITICAL` | ✅ Implemented | High-privilege Graph app permissions (`AppRoleAssignment.ReadWrite.All`, `RoleAssignment.ReadWrite.All`, `Application.ReadWrite.All`) |
| **`AZURE_03`** | RCE via Virtual Machine Contributor | Privilege Escalation | `HIGH` | ✅ Implemented | Service Principal assigned `Virtual Machine Contributor` capable of arbitrary root execution via Azure RunCommand |
| **`AZURE_04`** | Secret Harvesting via Key Vault Secrets Officer | Privilege Escalation | `HIGH` | ✅ Implemented | Service Principal assigned `Key Vault Administrator` or `Secrets Officer` enabling direct data-plane secret extraction |
| **`AZURE_05`** | Stale or Never-Expiring Service Principal Credentials | Credential Security | `MEDIUM` | ✅ Implemented | Client secret (`passwordCredentials`) or cert (`keyCredentials`) exceeding 180-day lifespan or configured with no expiry |

### 🟥 GCP IAM & Service Account Rules

| Rule ID | Name | Category | Severity | Status | Attack Vector / Detection |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`GCP_01`** | Service Account Impersonation (`TokenCreator`) | Privilege Escalation | `CRITICAL` | ✅ Implemented | Service Account bound to `roles/iam.serviceAccountTokenCreator`, enabling minting OAuth tokens as other SAs |
| **`GCP_02`** | Persistent Backdoor Key Creation (`KeyAdmin`) | Privilege Escalation | `CRITICAL` | ✅ Implemented | Service Account bound to `roles/iam.serviceAccountKeyAdmin`, enabling creation of out-of-band user-managed private keys |
| **`GCP_03`** | Workload Attachment (`ServiceAccountUser`) | Privilege Escalation | `HIGH` | ✅ Implemented | Service Account bound to `roles/iam.serviceAccountUser`, enabling attachment of privileged SAs to compute workloads |
| **`GCP_04`** | Direct Project Policy Manipulation (`setIamPolicy`) | Privilege Escalation | `CRITICAL` | ✅ Implemented | Service Account assigned `roles/iam.securityAdmin` or `roles/resourcemanager.projectIamAdmin` allowing direct IAM rewriting |
| **`GCP_05`** | Serverless Privilege Escalation | Privilege Escalation | `HIGH` | ✅ Implemented | Service Account granted `roles/cloudfunctions.developer` or `roles/run.developer` to deploy code executing under default SA |
| **`GCP_06`** | Stale User-Managed Service Account Keys | Credential Security | `MEDIUM` | ✅ Implemented | User-managed SA key older than 90 days (`validAfterTime`), indicating rotation failure |

**Detection methodology sources:** Rules are informed by Rhino Security Labs' documented AWS IAM privilege escalation research (21 methods), NetSPI and SpecterOps Azure attack paths, Rhino Security Labs GCP privilege escalation vectors, Salesforce's Cloudsplaining policy-severity methodology, CIS Foundations Benchmarks, and cloud vendor best practices.

### Example Security Finding

```json
{
  "RuleID": "AWS_03",
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

- **Baseline Ceiling (`Allow *`):** Leaves routine operational read/write actions untouched so services do not crash.
- **Hard Deny Guardrails:** Explicitly denies dangerous escalation actions (`iam:PutUserPermissionsBoundary`, `iam:DeleteRolePermissionsBoundary`, `iam:DeleteUserPermissionsBoundary`, `iam:PassRole`, `iam:CreatePolicyVersion`, etc.) so the identity cannot strip its own boundary ceiling or escalate permissions.
- **Non-Destructive Key Deactivation:** Stale and unused keys are toggled to `Inactive` rather than deleted, providing instant emergency rollback capabilities.
- **Exemption Management:** Protected identities (break-glass roles, runner identities) are defined in `nhi-ignore.yaml` and skipped automatically.

---

## 🔬 AST Policy Surgery (`nhi/remediation/policy_surgery.py`)

In addition to coarse-grained Permissions Boundary ceilings, the engine provides in-place **AST (Abstract Syntax Tree) Policy Surgery** to safely partition and scope over-permissive IAM policy statements without service downtime:

1. **Intelligent Action Partitioning (`is_non_resource_action`):**
   AWS IAM requires `Resource: "*"` for non-resource discovery actions (e.g., `ec2:Describe*`, `s3:ListAllMyBuckets`, `iam:GetAccountAuthorizationDetails`). Naive scanners that blindly replace `*` with target ARNs cause AWS IAM API validation errors or break operational monitoring. The surgery engine accurately partitions actions into discovery vs. resource-scoped operations.
2. **Statement Splitting:**
   When an `Allow` statement mixes discovery APIs with sensitive mutations (e.g., `ec2:Describe*` with `s3:PutObject` on `*`), the document is programmatically partitioned into two statements:
   - `{base_sid}Discovery`: Retains discovery actions with `Resource: "*"`.
   - `{base_sid}Scoped`: Scopes mutating actions (`Put*`, `Delete*`, `Decrypt`, etc.) to explicit target ARNs (`arn:aws:s3:::my-bucket/*`).
3. **`Sid` Idempotence:**
   Statements already isolated to discovery-only or scoped-only operations preserve their existing `Sid` deterministically without accumulating duplicate suffixes across recurring scans.
4. **Condition & Deny Preservation:**
   All `Condition` blocks, `NotAction`, `NotResource`, and `Deny` statements remain intact with zero syntactic mutations.

---

## ⚙️ Configuring Exemptions (`nhi-ignore.yaml`)

Automated containment checks findings against `nhi-ignore.yaml` before executing actions. Define your critical infrastructure identities to prevent automated containment:

```yaml
version: "1.0"
exemptions:
  # 1. CORE ADMINISTRATOR & PIPELINE USERS
  users:
    - name: "pam-suite-admin"
      reason: "Emergency break-glass administrator; exempt from automated boundaries"
      rules: ["*"]

    - name: "terraform"
      reason: "Terraform deployment user; requires full resource provisioning access"
      rules: ["*"]

    - name: "nhi-automation-runner-dev"
      reason: "Execution identity for NHI scanner; must avoid self-containment"
      rules: ["*"]

  # 2. AUTOMATION & AWS SERVICE-LINKED ROLES
  roles:
    - name: "nhi-automation-runner-role-dev"
      reason: "Execution role for inventory collection, S3 export, and remediation dispatcher"
      rules: ["*"]

    - name: "AWSServiceRoleForAccessAnalyzer"
      reason: "AWS Service-Linked Role"
      rules: ["*"]

    - name: "AWSServiceRoleForResourceExplorer"
      reason: "AWS Service-Linked Role"
      rules: ["*"]

    - name: "AWSServiceRoleForSupport"
      reason: "AWS Service-Linked Role"
      rules: ["*"]

    - name: "AWSServiceRoleForTrustedAdvisor"
      reason: "AWS Service-Linked Role"
      rules: ["*"]

  # 3. IAM GROUPS (Permissions boundaries not supported on IAM groups by AWS)
  groups:
    - name: "test-group"
      reason: "IAM groups do not support Permissions Boundaries in AWS IAM APIs"
      rules: ["*"]
```

- **Exempt All Rules:** `rules: ["*"]`
- **Exempt Specific Rules:** `rules: ["AWS_01", "AWS_03"]` (allows credential hygiene deactivations `AWS_11`/`AWS_12` while skipping policy boundaries).

---

## 🔌 Extending Detection & Remediation

The architecture decouples offline rule evaluation from remediation dispatching, making it straightforward to plug in new risk rules and containment handlers.

### 1. Adding a New Privilege Escalation / Risk Rule

1. Create or update a rule file in `nhi/risk/rules/` (e.g., `privilege_escalation.py`).
2. Define the detector returning standard finding payloads (`RuleID`, `IdentityType`, `IdentityName`, `Severity`, `Finding`).
3. Register the rule call inside `nhi/risk/risk.py`.

### 2. Adding a Targeted Remediation Handler

1. Create a handler function inside `nhi/remediation/handlers/` with the signature:
   ```python
   def handle_custom_remediation(finding: dict, dry_run: bool = True) -> bool:
       # Return True on success / simulated success, False on failure
   ```
2. Map the corresponding `RuleID` to the new handler in `nhi/remediation/dispatch.py`:
   ```python
   HANDLER_MAP = {
       ...
       "AWS_09": handle_custom_remediation,
   }
   ```
3. Add unit tests with mock injections under `tests/`.

---

## 🔮 Target Expansion Vectors (Roadmap)

### Planned Privilege Escalation Rules (Rhino Security Taxonomy)

- **`iam:UpdateAssumeRolePolicy`**: Modify existing role trust policies to allow self-assumption.
- **`iam:AttachGroupPolicy` / `iam:AddUserToGroup`**: Escalate privileges via high-privilege IAM group membership.
- **`lambda:UpdateFunctionCode` / `lambda:CreateFunction` + `iam:PassRole`**: Serverless execution role abuse.
- **`glue:CreateDevEndpoint` / `glue:UpdateDevEndpoint`**: Escalation via AWS Glue developer service roles.
- **`cloudformation:CreateStack`**: CloudFormation template execution role privilege escalation.

### Planned Remediation Modes

- **Surgical Policy Stripping (Phase 5):** Parse inline JSON policy documents and rewrite wildcard statements (`*`) to explicit, least-privilege action lists without attaching boundary ceilings.
- **Direct Admin Policy Detachment:** Programmatically detach AWS-managed root policies (`AdministratorAccess`) for unexempted machine roles.
- **Automated Rollback Ledger:** Record remediation actions to an S3-backed rollback journal allowing instant, one-click state reversion.

---

## 🗺️ Project Roadmap

### Completed Milestones

- [x] **Phase 1: AWS Infrastructure Foundation**
  - Infrastructure as Code via Terraform (`terraform/`)
  - Least-privilege IAM architecture and assume-role execution
  - Secure remote S3 state backend with encryption & versioning

- [x] **Phase 2: Discovery Engine & Ingestion**
  - IAM Users, Groups, Roles, Managed Policies & Inline Policies discovery
  - Access Key metadata enrichment (`GetAccessKeyLastUsed`)
  - Session caching for Boto3 API pagination
  - Snapshot export to local `inventory.json` and remote S3

- [x] **Phase 3: Risk Evaluation Engine**
  - Modular security rules (`wildcards.py`, `credentials.py`, `privilege_escalation.py`, `data_perimeter.py`, `resource_protection.py`, `tags.py`, `trust_policy.py`)
  - Detection for wildcard actions/resources, admin access, stale keys, unused/dormant keys, documented IAM privilege escalation paths, public trust policies, S3 data exfiltration, KMS decryption, and security defense evasion

- [x] **Phase 4: Automated Remediation Engine (Containment V1)**
  - Permissions Boundary containment for privilege escalation and policy over-privilege (`nhi/remediation/handlers/policy.py`)
  - Non-destructive access key deactivation (`nhi/remediation/handlers/credential.py`)
  - Dispatch pipeline with `dry_run` simulation and `nhi-ignore.yaml` exemptions (`nhi/remediation/dispatch.py`)
  - Run-over-run diffing engine with S3-backed state persistence (`nhi/remediation/diff.py`)
  - Standalone CLI packaging via `pyproject.toml` (`nhi` command) with custom `--csv` and OASIS SARIF v2.1.0 (`--sarif`) report exports
  - 100% offline unit test suite with `pytest` (`tests/test_remediation.py`, `tests/test_diff.py`, `tests/test_sarif.py`)

- [x] **Phase 5: Multi-Cloud Discovery & Unified Risk Engine (Azure & GCP)**
  - Pure REST ingestion layers for Azure (`nhi/azure/`) and GCP (`nhi/gcp/`) eliminating bulky SDKs and native `grpcio` dependencies
  - Cross-cloud inventory normalization in `nhi/services/inventory.py`
  - Decoupled provider sub-runners (`nhi/risk/runners/`) with selective `--cloud {aws,azure,gcp,all}` CLI targeting
  - Comprehensive privilege escalation and credential rules for Azure (`AZURE_01`–`AZURE_05`) and GCP (`GCP_01`–`GCP_06`)
  - 102 passing unit tests across all multi-cloud discovery and risk engines

- [x] **Phase 6: AST Policy Surgery Foundation**
  - Intelligent action partitioning (`is_non_resource_action`) separating non-resource discovery APIs from resource-scoped operations
  - Statement splitting into `{base_sid}Discovery` and `{base_sid}Scoped`
  - Deterministic `Sid` idempotence preventing duplicate suffix accumulation
  - Condition block and Deny preservation

---

### 🔮 Future Architectural Planning

#### Phase 7: 3-Tier Remediation Architecture & Automated Rollback Ledger

The platform is expanding beyond coarse boundary ceilings into a defense-in-depth, **3-Tier Remediation Model**:

- **Tier 1 — Permissions Boundary Containment & Key Deactivation (Implemented / Hardening):**
  - Attaches fail-closed Permissions Boundaries (`nhi-permissions-boundary`) to over-privileged identities to neutralize escalation vectors while preserving normal service read/write workloads (`nhi/remediation/handlers/policy.py`).
  - Non-destructive credential deactivation toggling stale/dormant keys to `Inactive` for instant emergency rollback (`nhi/remediation/handlers/credential.py`).
- **Tier 2 — Direct Root Policy Detachment & Multi-Cloud Credential Revocation (Planned):**
  - Dedicated handler for `AWS_03` to cleanly detach root-equivalent managed policies (`AdministratorAccess`) from unexempted machine identities.
  - Multi-cloud credential containment: Automated deactivation of expired Entra ID app credentials (`AZURE_05`) and disabling of stale GCP user-managed service account keys (`GCP_06`).
- **Tier 3 — AST Policy Surgery & GitOps PR Generation (Core Engine Built, Live Pipeline Planned):**
  - Automated AST document rewrites via `policy_surgery.py` to rewrite inline/attached policies into least-privilege definitions.
  - Statement partitioning: separating discovery APIs (`Describe*`, `List*`) from scoped resource mutations (`Put*`, `Get*`, `Decrypt`).
  - S3 Rollback Journal: Writing immutable pre-surgery snapshots to an S3 ledger before executing cloud mutations for instant, one-click state reversion.
  - GitOps Integration: Generating pull requests with minimal unified JSON/Terraform HCL diffs for team peer-review before production apply.
- **Target-Level Remediation Deduplication:** Coalesce multi-finding dispatches to execute single, unified remediation calls per identity.

#### Phase 8: Team Communication & Event Notifications

- **Slack & Microsoft Teams Webhooks:** High/Critical findings pushed to dedicated SecOps channels with interactive "Acknowledge" or "Remediate" buttons.
- **Jira / ITSM Ticket Automation:** Automatic ticket generation for identified high-severity policy wildcards or dormant keys, assigning tasks directly to resource owner teams.
- **Event-Driven Architecture (AWS EventBridge / Lambda):** Trigger scans automatically upon IAM creation events (`CreateUser`, `CreateAccessKey`, `PutRolePolicy`). Authenticates serverless scanners keylessly via IAM execution roles and GitHub OIDC federation.

## ⚙️ Environment & Execution Setup

> **⚠️ Local development note:** the setup below uses a static IAM access key for the runner identity, sourced via `admin.sh`/`runner.sh`. This is a **temporary, local-dev-only pattern** — the runner's own Terraform-managed IAM user only holds `sts:AssumeRole` permission (see `terraform/main.tf`), with all actual scan/export/remediation permissions living on the assumed role, not the user. The static key exists solely to bootstrap that first `AssumeRole` call during local development and is not intended to ship in any deployed or public-facing version of this project. Planned replacements: **AWS IAM Identity Center (SSO)** for local/human use, and **GitHub OIDC federation** for the CI/CD `nhi-action` (Phase 6) — both eliminate the static key entirely by authenticating the caller directly and issuing short-lived credentials.

The scanner relies on environment variables set up via shell scripts (`admin.sh` and `runner.sh`) to extract Terraform outputs and configure execution session credentials.

### 1. Admin Credentials Script (`admin.sh`)

Create `admin.sh` (not committed — add to `.gitignore`) to export initial administrator credentials required for Terraform provisioning and bootstrap operations:

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

### 3. Azure Setup

Azure discovery uses `DefaultAzureCredential`, supporting local developer logins, service principal environment variables, or managed identities automatically:

```bash
# Required for Azure Resource Manager (ARM) queries
export AZURE_SUBSCRIPTION_ID="<YOUR_AZURE_SUBSCRIPTION_ID>"

# Local interactive development:
az login

# Or CI/CD Service Principal authentication:
export AZURE_CLIENT_ID="<SERVICE_PRINCIPAL_CLIENT_ID>"
export AZURE_CLIENT_SECRET="<SERVICE_PRINCIPAL_SECRET>"
export AZURE_TENANT_ID="<AZURE_TENANT_ID>"
```

### 4. GCP Setup

GCP discovery uses standard Application Default Credentials (ADC), supporting local user credentials, service account key files, or attached workload identities automatically:

```bash
# Explicit Project ID target (or auto-detected from credentials)
export GCP_PROJECT_ID="<YOUR_GCP_PROJECT_ID>"

# Local interactive development:
gcloud auth application-default login

# Or CI/CD Service Account authentication:
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account-key.json"
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
      "Action": ["s3:PutObject", "s3:GetObject"],
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
├── .github/
│   └── workflows/
│       └── nhi-scan.yml           # Automated CI/CD security scan via AWS OIDC & SARIF
├── docs/                          # Architecture blueprints, active tasks & interview trackers
│   ├── PRODUCT_BLUEPRINT.md       # 5-Layer Production SaaS Architecture & Blueprint
│   ├── ACTIVE_TASK.md             # Current active implementation tasks & specs
│   ├── INTERVIEW_PROGRESS_PRONG1_PROJECT.md # Project code mastery & Terraform drill tracker
│   └── INTERVIEW_PROGRESS_PRONG2_DEVSECOPS.md # Level 1-100 DevSecOps screener tracker
├── nhi/
│   ├── aws/                       # AWS Boto3 wrappers & session management
│   │   ├── iam.py                 # IAM API helpers
│   │   ├── s3.py                  # S3 upload & retrieval utilities
│   │   └── session.py             # Dual-mode (OIDC ambient + STS assume) session logic
│   ├── azure/                     # Azure pure-REST discovery engine
│   │   ├── auth.py                # DefaultAzureCredential & Bearer token management
│   │   ├── graph.py               # Microsoft Graph API client (SP, App Regs, Creds)
│   │   └── arm.py                 # Azure Resource Manager client (RBAC, Role Assigns)
│   ├── gcp/                       # GCP pure-REST discovery engine
│   │   ├── auth.py                # Application Default Credentials (ADC) token management
│   │   ├── iam.py                 # GCP IAM REST client (Service Accounts & Keys)
│   │   └── resourcemanager.py     # GCP Resource Manager REST client (Project IAM Policy)
│   ├── remediation/               # Automated remediation & diffing engine
│   │   ├── dispatch.py            # Handler routing & stats collection
│   │   ├── diff.py                # Posture drift & diffing logic
│   │   ├── config.py              # Exemption parser for nhi-ignore.yaml
│   │   ├── policy_surgery.py      # AST policy statement partitioning & ARN scoping
│   │   └── handlers/              # Boundary & deactivation logic
│   ├── risk/                      # Core multi-cloud evaluation engine
│   │   ├── risk.py                # Main CLI runner & orchestrator (--cloud support)
│   │   ├── helpers.py             # Non-resource action classification & helpers
│   │   ├── runners/               # Decoupled provider sub-runners
│   │   │   ├── aws.py             # AWS risk checks sub-runner
│   │   │   ├── azure.py           # Azure RBAC & Entra ID sub-runner
│   │   │   └── gcp.py             # GCP IAM & Service Account sub-runner
│   │   └── rules/                 # Modular risk detection rules
│   │       ├── aws/               # AWS rules (AWS_01-AWS_16, TAG_01)
│   │       ├── azure/             # Azure rules (AZURE_01-AZURE_05)
│   │       └── gcp/               # GCP rules (GCP_01-GCP_06)
│   ├── services/
│   │   ├── export.py              # JSON and CSV output handlers
│   │   ├── inventory.py           # Multi-cloud state collection orchestrator
│   │   └── sarif.py               # OASIS SARIF v2.1.0 report generator
│   └── config.py                  # Global threshold configurations
├── terraform/                     # Infrastructure as Code
│   ├── oidc.tf                    # AWS OIDC Provider & GitHub Actions IAM role
│   ├── main.tf                    # Runner role, baseline policies, boundary definition
│   ├── outputs.tf                 # Exported ARNs (including oidc_role_arn)
│   ├── canary.tf                  # Canary IAM entities for detection validation
│   └── remote_state.tf            # S3 remote backend & state locking
├── tests/                         # Pytest 100% offline unit testing suite (102 tests)
├── .gitignore                     # Untracked files configuration
├── admin.sh                       # Local admin bootstrap (gitignored)
├── automation_test.py             # Local testing and automation script
├── license.md                     # AGPLv3 License
├── nhi-ignore.yaml                # Remediation exemption list
├── pyproject.toml                 # Package configuration & CLI entry point
├── pytest.ini                     # Pytest environment config
├── README.md                      # Project documentation
└── runner.sh                      # Local session setup script (gitignored)
```

---

## 🚀 Quick Start Guide

### Prerequisites

- Python 3.10+
- Terraform 1.5+
- AWS CLI configured

### 1. Clone & Setup Virtual Environment

```bash
git clone https://github.com/likithmanoj/nhi-risk-analyzer.git
cd nhi-risk-analyzer

python3 -m venv .venv
source .venv/bin/activate

# Install dependencies and package CLI in editable mode
pip install -e .
```

### 2. Bootstrap the Remote State Backend (first-time setup only)

The S3 bucket that stores Terraform's remote state is itself a Terraform-managed resource (`terraform/remote_state.tf`), which means it can't be its own backend on the very first apply. This was solved in two passes:

```bash
source admin.sh
cd terraform
```

**Pass 1 — create the backend bucket while still using local state:**

```bash
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

```text
Do you want to copy existing state to the new backend?
```

Answering `yes` copies the local `terraform.tfstate` into the S3 backend. From this point on, Terraform reads and writes remote state instead of the local file.

> **Provider version conflict during migration:** if the remote state was created with a newer AWS provider version than your local config is constrained to (e.g. state written with provider `6.x`, local config pinned to `~> 5.0`), migration can fail with `Resource instance managed by newer provider version` — the older provider can't decode state written by a newer provider's schema. Fix by updating `required_providers` to match the newer version:
>
> ```hcl
> required_providers {
>   aws = {
>     source  = "hashicorp/aws"
>     version = "~> 6.0"
>   }
> }
> ```
>
> then clear the local provider cache and lock file before reinitializing:
>
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

cd ..
```

Skip this whole bootstrap on subsequent clones/machines once the backend is already configured in the repo — `terraform init` alone will pull the existing remote state.

### 3. Provision Infrastructure via Terraform

```bash
source admin.sh
cd terraform
terraform apply -auto-approve
cd ..
```

### 4. Source Credentials & Execute Discovery / Risk Analysis

The execution engine provides multi-cloud provider targeting via `--cloud` alongside flexible scan, export, and containment modes:

```bash
# Source dynamically generated runner credentials and boundary ARN
source runner.sh

# -------------------------------------------------------------
# Multi-Cloud Provider Targeting (--cloud {aws,azure,gcp,all})
# -------------------------------------------------------------
# 1. Full Multi-Cloud Scan (Default: evaluates all configured clouds)
nhi

# 2. Target specific clouds to eliminate unnecessary API overhead & rate limits:
nhi --cloud aws
nhi --cloud azure
nhi --cloud gcp

# -------------------------------------------------------------
# Export & Security Reporting
# -------------------------------------------------------------
# 3. Export Multi-Cloud findings to CSV for auditing:
nhi --cloud all --csv findings.csv

# 4. Export findings to OASIS SARIF v2.1.0 for CI/CD ingestion:
nhi --cloud all --sarif results.sarif

# -------------------------------------------------------------
# Remediation & Dry-Run Simulation
# -------------------------------------------------------------
# 5. Dry-Run Simulation (Simulates containment & validates nhi-ignore.yaml exemptions):
nhi --cloud aws --dry-run

# 6. Combined Dry-Run simulation with SARIF export:
nhi --cloud aws --dry-run --sarif security-scan.sarif

# 7. Live Containment Mode (Attaches Permissions Boundaries & deactivates stale keys):
nhi --cloud aws --remediate
```

---

## 🚀 CI/CD & GitHub Actions Integration (Keyless via AWS OIDC)

`nhi-risk-analyzer` runs natively inside GitHub Actions with **zero long-lived AWS access keys** by combining **AWS OpenID Connect (OIDC)** identity federation with **OASIS SARIF v2.1.0** security reporting.

```text
  ┌──────────────────────┐         ┌────────────────────┐         ┌────────────────────┐
  │  GitHub Actions CI   │  OIDC   │   AWS STS Service  │ Assume  │   NHI Assessment   │
  │  (.github/workflows) │ ──────> │  (Trust Policy)    │ ──────> │   (OIDC-Assumed    │
  │  Mints Signed JWT    │         │  Validates Claims  │  Role   │    Permissions)    │
  └──────────────────────┘         └────────────────────┘         └────────────────────┘
             │                                                               │
             │                                                               │
             ▼                                                               ▼
  ┌──────────────────────┐         ┌────────────────────┐         ┌────────────────────┐
  │ GitHub Security Tab  │ <────── │ upload-sarif@v3    │ <────── │  `results.sarif`   │
  │ Code Scanning Alerts │  SARIF  │ Ingests Findings   │ Output  │  OASIS v2.1.0 JSON │
  └──────────────────────┘         └────────────────────┘         └────────────────────┘
```

### Step 1: Provision OIDC Trust in Your AWS Account

Deploy the provided Terraform configuration in `terraform/oidc.tf` into your target AWS account.

In `terraform/oidc.tf`, update the `sub` claim condition to trust your own GitHub organization and repository:

```hcl
condition {
  test     = "StringLike"
  values   = ["repo:<YOUR_GITHUB_ORG>/<YOUR_REPO>:*"]
  variable = "token.actions.githubusercontent.com:sub"
}
```

Deploy the infrastructure:

```bash
cd terraform
terraform init
terraform apply
```

Terraform automatically displays the created role ARN in the outputs at the end of the apply. You can also view it at any time:

- **From the repository root:**
  ```bash
  terraform -chdir=terraform output oidc_role_arn
  ```
- **From inside the `terraform/` directory:**
  ```bash
  terraform output oidc_role_arn
  ```

### Step 2: Configure Your GitHub Repository Variable

Set the repository variable via the GitHub CLI (`gh`):

```bash
gh variable set AWS_ROLE_TO_ASSUME --body "arn:aws:iam::<YOUR_ACCOUNT_ID>:role/oidc-role"
```

_(Alternatively, configure it via the GitHub UI under **Settings → Secrets and variables → Actions → Variables → New repository variable**)._

### Step 3: Add the GitHub Actions Workflow

Create `.github/workflows/nhi-scan.yml` in your repository:

```yaml
name: NHI Security Scan & SARIF Export

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  workflow_dispatch:

permissions:
  id-token: write # Required for AWS OIDC authentication
  contents: read # Required for actions/checkout to pull your repository
  security-events: write # Required for GitHub Code Scanning to ingest SARIF

jobs:
  scan:
    name: Run NHI Risk Assessment
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Configure AWS Credentials via OIDC
        uses: aws-actions/configure-aws-credentials@v6
        with:
          role-to-assume: ${{ vars.AWS_ROLE_TO_ASSUME }}
          aws-region: us-east-1

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -e .

      - name: Run NHI Scan
        env:
          # Optional: Put your S3 bucket name here to save scan history & run-over-run diffs
          BUCKET_NAME: pam-infrastructure-automation-suite-dev-bucket
        run: |
          nhi --sarif results.sarif

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: results.sarif
          category: nhi-risk-analyzer
```

### 💡 S3 Bucket Setup (Simple Guide)

If you want GitHub Actions to store scan findings and compare results over time:

1. Open `.github/workflows/nhi-scan.yml`.
2. Find the **`Run NHI Scan`** step.
3. Update `BUCKET_NAME` with your own S3 bucket name:
   ```yaml
   env:
     BUCKET_NAME: your-bucket-name-here
   ```
4. **Don't want to use S3?** No problem! You can simply delete or comment out `BUCKET_NAME`. The scanner will still run, find all security risks, and upload them directly to GitHub Code Scanning without needing an S3 bucket.

### Step 4: View Findings in GitHub Code Scanning

Once the workflow finishes, all security alerts (Privilege Escalation, Permissive Trust Policies, Credential Hygiene, Data Perimeter breaches) appear directly inside your GitHub repository under **Security → Code scanning alerts** with full rule IDs, severity indicators, and remediation guidance.

---

## 🧪 Running Unit Tests

To run the full unit test suite offline without live AWS API dependencies:

```bash
pytest tests/ -v
```

---

## 📄 License

This project is licensed under the **GNU Affero General Public License v3.0 (AGPLv3)** - see the [LICENSE](license.md) file for details. Under AGPLv3, any modifications or network services (SaaS) built using this software must also make their complete source code publicly available under the same license terms.
