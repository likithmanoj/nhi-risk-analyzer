# NHI Risk Analyzer for AWS

A security automation platform that discovers, inventories, and (in progress) risk-scores Non-Human Identities (NHIs) — IAM users, roles, and their associated policies — in AWS environments.

## Overview

NHI Risk Analyzer is an engineering project focused on solving a real, unsolved problem: most AWS accounts accumulate hundreds of non-human identities (service accounts, automation roles, CI/CD credentials, cross-account roles) with no centralized, automated way to see which ones are over-privileged, dormant, or carrying dangerous permission combinations.

The project combines Infrastructure as Code, cloud security engineering, and Python automation to build a discovery and risk-analysis engine, backed by hands-on IAM/PAM operational experience rather than a generic tutorial approach.

## Why This Project Exists

Enterprise AWS environments routinely have non-human identities that are:

- Created manually, without a consistent provisioning standard
- Over-permissioned relative to what they actually use
- Left active long after the workload they served is gone
- Carrying both managed *and* inline policies, which most tooling only checks half of
- Never audited against actual usage data (who's using `iam:ListUsers` output without checking Access Advisor?)

This project automates that discovery and analysis using a real, working AWS integration — not mocked data.

## Current Features

### Infrastructure Provisioning (Terraform)
- AWS IAM User + Role provisioning with a correct least-privilege trust chain (User → `sts:AssumeRole` only → Role → scoped permissions)
- IAM Trust Policies via `aws_iam_policy_document` (not raw `jsonencode`, for native HCL validation)
- Remote state in S3: versioned, AES256-encrypted, all public access blocked, correctly bootstrapped (local apply → `terraform init -migrate-state`)
- Amazon S3 bucket provisioning with secure-by-default configuration
- Environment-based dynamic resource naming

### Discovery Engine (Python)
- STS AssumeRole-based authentication, abstracted behind a single session module
- Full pagination across every IAM list operation (users, roles, groups, managed policies, attached policies) — a naive implementation silently truncates at 100 results; this one doesn't
- Managed policy discovery for both users and roles
- **Inline policy discovery for both users and roles** — the policy surface most basic tooling misses entirely, since inline policies have no ARN and require a separate `get_*_policy` call per policy
- JSON export of the full inventory
- Automated upload of scan output to S3

## Project Architecture

```
Terraform
    │
    ▼
AWS Infrastructure
    │
    ├── IAM User (sts:AssumeRole only)
    ├── IAM Role (scoped permissions)
    ├── IAM Policies (least privilege)
    └── Amazon S3 (state + scan output)
            │
            ▼
    Python (nhi package)
            │
            ├── nhi/aws/session.py    → STS AssumeRole, single auth seam
            ├── nhi/aws/iam.py        → IAM discovery (paginated)
            ├── nhi/aws/s3.py         → scan output upload
            ├── nhi/services/inventory.py → orchestration
            └── nhi/services/export.py    → JSON export
            │
            ▼
    inventory.json → Amazon S3
```

The layering is deliberate: `session.py` is the only module that knows how authentication works, so swapping the auth mechanism later touches one file. `iam.py` and `s3.py` are leaves with no dependency on each other. `inventory.py` composes discovery output without knowing anything about credentials.

## Repository Structure

```
terraform/
├── main.tf
├── variables.tf
├── outputs.tf
├── providers.tf
├── remote_state.tf
├── s3.tf
└── .terraform.lock.hcl

nhi/
├── aws/
│   ├── session.py
│   ├── iam.py
│   └── s3.py
├── services/
│   ├── inventory.py
│   └── export.py
└── config.py

main.py          # entry point: discover → export → upload
README.md
.gitignore
```

## Roadmap

### Phase 1 — AWS Infrastructure Foundation
**Status: Complete** (one item held deliberately open — see below)
- IAM User/Role provisioning, least-privilege trust chain, remote S3 state, secure S3 bucket defaults
- **Open by choice:** the original bootstrap IAM access key resource is still present pending a full review of the credential-chain reasoning before removal — not an oversight, a deliberate hold.

### Phase 2 — NHI Discovery Engine
**Status: In progress, nearly complete**
- [x] Pagination across all IAM list operations
- [x] Role-attached (managed) policy coverage
- [x] Inline policy discovery (users and roles)
- [ ] Verify policy document parsing (confirm `PolicyDocument` is usable structured data, not a raw encoded string)
- [ ] Session caching (avoid redundant `AssumeRole` calls per discovery run)
- [ ] Structured error handling and logging

### Phase 3 — Risk Engine
**Status: Not started**
- Wildcard permission detection
- `AdministratorAccess` and equivalent over-privilege detection
- Dormant identity detection (via IAM Access Advisor)
- Access key age tracking
- Console users without MFA
- Weighted, multi-dimensional risk scoring with severity classification

### Phase 4 — Vault Migration Engine
**Status: Not started**
- Rotate high-risk flagged credentials into HashiCorp Vault as dynamic secrets with a TTL, replacing long-lived IAM keys
- Full before/after audit trail per rotation
- This is the project's core remediation story — not a text suggestion, an actual automated credential lifecycle change

### Phase 5 — Production Readiness
**Status: Not started**
- Reusable Terraform modules
- Unit test suite
- GitHub Actions CI (`terraform fmt`/`validate`, `pytest` on PR)
- Structured logging
- Architecture diagrams and full documentation

## Engineering Principles

This project is built around:

- Infrastructure as Code
- Principle of Least Privilege
- Secure by Default
- Temporary Credentials over long-lived keys
- Separation of Authentication and Authorization
- Modular, layered code architecture

## Current Status

**Status:** Active development. Phase 2 (Discovery Engine) is close to complete, with policy document verification, session caching, and error handling remaining before Phase 3 (Risk Engine) begins. The project's differentiator — Vault-based credential migration in Phase 4 — is planned but not yet started.