# NHI Risk Analyzer for AWS

A security automation platform that discovers, inventories, analyzes, and risk-assesses Non-Human Identities (NHIs) — IAM users, groups, roles, and their associated policies — across AWS environments.

---

## Overview

NHI Risk Analyzer is an engineering project focused on solving a real cloud security problem: enterprise AWS environments accumulate hundreds of non-human identities (service accounts, automation roles, CI/CD credentials, cross-account roles) with little visibility into which identities are over-privileged, dormant, or introduce privilege-escalation risk.

The project combines Infrastructure as Code, cloud security engineering, and Python automation to build a discovery and risk-analysis engine backed by real AWS integrations rather than mocked data or tutorial examples.

---

## Why This Project Exists

Enterprise AWS environments routinely contain non-human identities that are:

- Created manually without a consistent provisioning standard
- Over-permissioned relative to their actual usage
- Left active long after the workload they served has been decommissioned
- Carrying both managed and inline IAM policies, where many tools only inspect one
- Rarely audited against actual permissions or usage data

NHI Risk Analyzer automates discovery and security analysis using live AWS APIs.

---

# Current Features

## Infrastructure Provisioning (Terraform)

- AWS IAM User + Role provisioning using a least-privilege trust chain
- IAM Trust Policies generated using `aws_iam_policy_document`
- Secure remote Terraform state stored in Amazon S3
- Versioned and encrypted S3 bucket configuration
- Environment-aware resource naming
- Secure-by-default infrastructure provisioning

---

## Discovery Engine (Python)

- STS AssumeRole-based authentication
- Module-level AWS Session caching
- Full IAM pagination support
- IAM User discovery
- IAM Group discovery
- IAM Role discovery
- Managed policy discovery
- Inline policy discovery
- Complete inventory generation
- JSON inventory export
- Automated upload to Amazon S3

---

## Risk Engine (Python)

Currently implemented:

- Wildcard IAM Action detection
- Analysis of both Attached and Inline policies
- User policy analysis
- Group policy analysis
- Role policy analysis
- Shared policy analysis module
- Structured security findings
- Severity classification

Example finding:

```json
{
  "IdentityType": "User",
  "IdentityName": "pam-suite-admin",
  "PolicyName": "IAMFullAccess",
  "Action": "iam:*",
  "Finding": "Wildcard Action",
  "Severity": "HIGH"
}
```

---

# Engineering Optimizations

## AWS Session Caching

To eliminate redundant AWS authentication, authenticated boto3 Sessions are cached for the lifetime of the Python process.

Measured improvement:

- STS AssumeRole calls reduced from **35 → 1**
- Inventory execution time improved from **79.58s → 45.67s**
- Approximately **43% reduction in runtime**

The optimization required no changes to the inventory or IAM discovery modules because authentication remains fully encapsulated within `session.py`.

---

# Project Architecture

```
Terraform
        │
        ▼
AWS Infrastructure
        │
        ▼
Python (nhi package)
        │
        ├── aws/
        │      ├── session.py
        │      ├── iam.py
        │      └── s3.py
        │
        ├── services/
        │      ├── inventory.py
        │      └── export.py
        │
        ├── risk/
        │      ├── risk.py
        │      └── analyze_policy.py
        │
        └── config.py
                │
                ▼
        Findings + Inventory
                │
                ▼
             Amazon S3
```

### Architectural Principles

- Authentication is isolated inside `session.py`
- Discovery logic is isolated from authentication
- Risk analysis is isolated from inventory collection
- Policy analysis is reusable across Users, Groups and Roles
- Security findings are generated independently of discovery

---

# Repository Structure

```
terraform/
├── main.tf
├── providers.tf
├── variables.tf
├── outputs.tf
├── remote_state.tf
└── s3.tf

nhi/
├── aws/
│   ├── session.py
│   ├── iam.py
│   └── s3.py
│
├── services/
│   ├── inventory.py
│   └── export.py
│
├── risk/
│   ├── risk.py
│   └── analyze_policy.py
│
└── config.py

README.md
.gitignore
```

---

# Roadmap

## Phase 1 — AWS Infrastructure Foundation

**Status: ✅ Complete**

Completed:

- ✅ Least-privilege IAM architecture
- ✅ Remote Terraform state
- ✅ Secure S3 configuration
- ✅ IAM trust relationships
- ✅ Infrastructure provisioning

---

## Phase 2 — Discovery Engine

**Status: ✅ Complete**

Completed:

- ✅ IAM User discovery
- ✅ IAM Group discovery
- ✅ IAM Role discovery
- ✅ Full IAM pagination
- ✅ Managed policy discovery
- ✅ Managed policy document retrieval
- ✅ Inline policy discovery
- ✅ Inline policy document retrieval
- ✅ IAM role trust policy collection
- ✅ Session caching
- ✅ JSON inventory export
- ✅ Amazon S3 upload

Future improvements:

- Performance optimization and policy caching
- Structured logging
- Error handling
- Inventory caching

---

## Phase 3 — Risk Engine

**Status: 🚧 In Progress**

Completed:

- ✅ Wildcard IAM Action detection
- ✅ Shared policy analysis engine
- ✅ Analysis of Users, Groups and Roles
- ✅ Structured security findings
- ✅ Severity classification

Planned:

- ⏳ Wildcard Resource detection
- ⏳ AdministratorAccess detection
- ⏳ Trust Policy analysis
- ⏳ Cross-account trust detection
- ⏳ Public (`Principal: "*"`) trust detection
- ⏳ Dormant identity detection (IAM Access Advisor)
- ⏳ Access Key Age analysis
- ⏳ Console users without MFA
- ⏳ Weighted risk scoring
- ⏳ Risk report generation

---

## Phase 4 — Automated Remediation

**Status: ⏳ Planned**

- Policy-driven remediation engine
- Credential rotation
- Secrets backend integration (HashiCorp Vault and/or AWS Secrets Manager)
- Audit trail generation
- Automated remediation workflows

---

## Phase 5 — Production Readiness

**Status: ⏳ Planned**

- Unit testing
- GitHub Actions CI
- Terraform validation
- Structured logging
- Performance benchmarking
- Documentation
- Architecture diagrams

---

# Current Status

**Status: Active Development**

Completed:

- ✅ AWS Infrastructure Foundation
- ✅ Discovery Engine
- ✅ Managed & Inline Policy Collection
- ✅ IAM Trust Policy Collection
- ✅ Wildcard Risk Detection
- ✅ Shared Policy Analysis Engine
- ✅ AWS Session Caching

Currently Building:

- 🚧 Risk Engine (additional detection rules)

Long-Term Goal:

Build an enterprise-grade Non-Human Identity (NHI) security platform capable of discovering, analyzing, risk-scoring, and remediating IAM identities across AWS environments.