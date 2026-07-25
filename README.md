# NHI Infrastructure Automation Suite

> A security automation platform for provisioning, auditing, and migrating Non-Human Identities (NHIs) across cloud environments and enterprise Privileged Access Management (PAM) platforms.

---

# Overview

NHI Infrastructure Automation Suite is a long-term engineering project focused on automating the lifecycle of Non-Human Identities (NHIs), including service accounts, machine identities, API keys, and application credentials.

The project combines Infrastructure as Code, cloud security, and Python automation to build reusable tooling inspired by real-world enterprise Identity and Access Management (IAM), cloud security, and Privileged Access Management (PAM) operations.

---

# Why This Project Exists

Enterprise environments often manage thousands of non-human identities across cloud platforms and privileged access management solutions.

These identities are frequently:

- Created manually
- Managed through support tickets
- Audited using spreadsheets
- Over-permissioned
- Poorly documented
- Rotated inconsistently
- Difficult to migrate between PAM platforms

This project aims to automate those operational workflows using modern cloud-native technologies while following security engineering best practices.

---

# Current Features

## Infrastructure Provisioning

- AWS IAM User provisioning
- IAM Role provisioning
- IAM Trust Policies
- IAM Permission Policies
- IAM Role Policy Attachments
- Environment-based deployments
- Dynamic resource naming
- Terraform Outputs for runtime configuration

## Amazon S3

- Bucket provisioning
- Public Access Block configuration
- Server-Side Encryption (SSE-S3)
- Secure infrastructure defaults

## Python Automation

- boto3 integration
- Automated S3 uploads
- Environment variable configuration
- AWS STS AssumeRole authentication
- Temporary AWS credential generation
- Error handling

## Security

- Least Privilege IAM Policies
- AWS Security Token Service (STS)
- IAM Role AssumeRole
- Temporary security credentials
- Trust-based role assumption
- Separation of authentication and authorization
- Infrastructure as Code
- Security-first resource provisioning

---

# Project Architecture

```text
Terraform
      │
      ▼
AWS Infrastructure
      │
      ├── IAM User
      ├── IAM Role
      ├── IAM Policies
      ├── Trust Policies
      └── Amazon S3
              │
              ▼
runner.sh
              │
              ▼
Python (boto3)
              │
              ▼
AWS STS AssumeRole
              │
              ▼
Temporary Credentials
              │
              ▼
Amazon S3
```

---

# Repository Structure

```text
terraform/
│
├── main.tf
├── variables.tf
├── outputs.tf
├── providers.tf
├── terraform.tfvars
└── backend.tf

automation_test.py
admin.sh
runner.sh
README.md
.gitignore
```

---

# Roadmap

## Phase 1 — AWS Infrastructure Foundation

### Completed

- AWS IAM User provisioning
- IAM Policy creation
- IAM Role implementation
- Trust Policy implementation
- IAM Role Policy Attachments
- Amazon S3 provisioning
- Public Access Block configuration
- Server-Side Encryption (SSE-S3)
- Remote Terraform State (S3 Backend)
- Python boto3 integration
- Environment parameterization
- AWS STS AssumeRole implementation
- Temporary credential authentication
- Terraform Outputs for runtime configuration
- Role-based S3 authentication

### In Progress

- DynamoDB State Locking
- IAM Access Key rotation
- Improve Terraform project structure
- Environment-specific deployments (Dev / QA / Prod)

---

## Phase 2 — CyberArk Foundation

- Authentication
- Safe discovery
- Account discovery
- Mock CyberArk API client
- JSON export

---

## Phase 3 — NHI Audit Scanner

Python-based security audit engine capable of identifying:

- Dormant identities
- Over-privileged IAM policies
- Wildcard permissions
- Missing credential rotation
- Expired credentials
- Risk findings exported as JSON

---

## Phase 4 — Migration Toolkit

Migration workflows for enterprise PAM platforms.

Planned support includes:

- CyberArk → AWS Secrets Manager
- CyberArk → HashiCorp Vault
- Bulk identity migration
- Migration validation reports

---

## Phase 5 — Production Readiness

- Terraform Modules
- Unit Tests
- Logging
- CloudTrail integration
- CloudWatch monitoring
- CI/CD
- GitHub Actions
- Architecture Documentation

---

# Engineering Principles

This project is built around:

- Infrastructure as Code
- Principle of Least Privilege
- Secure by Default
- Zero Trust
- Temporary Credentials
- Role-Based Access Control (RBAC)
- Reusable Automation
- Environment Isolation
- Modular Infrastructure

---

# Project Goals

- Automate provisioning of Non-Human Identities
- Reduce manual IAM and PAM administration
- Build reusable Terraform modules
- Automate cloud security tasks using Python
- Demonstrate production-oriented security engineering practices
- Implement secure AWS authentication patterns
- Explore migration paths between enterprise PAM platforms and cloud-native identity services

---

# Current Status

**Status:** Active Development

The project is currently focused on building a production-inspired automation platform for managing Non-Human Identities across AWS and enterprise PAM ecosystems.

The AWS infrastructure foundation has been established, including secure IAM architecture, role-based authentication using AWS STS, Infrastructure as Code with Terraform, and Python automation using temporary credentials.

Future phases will expand the platform into identity auditing, CyberArk integration, migration tooling, and enterprise-scale automation workflows.