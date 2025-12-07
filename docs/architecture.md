# Compliance-as-Code Framework Architecture

## Table of Contents
- [Overview](#overview)
- [Design Principles](#design-principles)
- [System Architecture](#system-architecture)
- [Components](#components)
- [Data Flow](#data-flow)
- [Integration Points](#integration-points)
- [Security Considerations](#security-considerations)
- [Scalability & Performance](#scalability--performance)

---

## Overview

The Compliance-as-Code (CaC) framework is designed to automate compliance validation, enforcement, and remediation across multi-cloud environments. It implements a defense-in-depth approach with three layers:

1. **Shift-Left**: Pre-deployment validation in the development pipeline
2. **Runtime Monitoring**: Continuous scanning of deployed resources
3. **Enforcement**: Automatic remediation and blocking of violations

### Key Goals
- **Automation**: Minimize manual compliance checks
- **Prevention**: Block non-compliant configurations before deployment
- **Visibility**: Real-time compliance posture dashboard
- **Auditability**: Complete evidence trail for auditors
- **Remediation**: Auto-fix violations when safe

---

## Design Principles

### 1. Policy as Code
All compliance requirements are expressed as executable code:
- **Rego** (OPA) for declarative policies
- **Python/Ruby** for runtime checks (InSpec)
- **YAML** for remediation workflows (Custodian, Ansible)

### 2. Fail-Safe Defaults
- Default to blocking non-compliant deployments
- Require explicit exceptions with justification
- Audit all exception grants

### 3. Defense in Depth
Multiple layers of validation:
```
Developer Workstation → Pre-commit Hooks
         ↓
Git Repository → CI/CD Pipeline Checks
         ↓
Deployment → Admission Control (OPA Gatekeeper)
         ↓
Runtime → Continuous Scanning (InSpec, ScoutSuite)
         ↓
Enforcement → Auto-remediation (Custodian, Config)
```

### 4. Separation of Concerns
- **Policy Definition**: Controls library (config/controls/)
- **Policy Implementation**: Check implementations (policies/, tests/)
- **Enforcement Logic**: Remediation scripts (remediation/)
- **Evidence Collection**: Audit logs (evidence/)

### 5. Least Privilege
- Scanner IAM roles with minimal read permissions
- Remediation roles with specific write permissions
- Separate roles for different compliance domains

---

## System Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Developer Layer                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌─────────────┐      ┌──────────────┐      ┌───────────────┐  │
│  │   VS Code   │ ───→ │ Pre-commit   │ ───→ │  Git Push     │  │
│  │   Terraform │      │ Hooks        │      │               │  │
│  └─────────────┘      │ - Checkov    │      └───────┬───────┘  │
│                       │ - tfsec      │              │           │
│                       │ - Conftest   │              │           │
│                       └──────────────┘              │           │
└─────────────────────────────────────────────────────┼───────────┘
                                                      │
                                                      ↓
┌─────────────────────────────────────────────────────────────────┐
│                         CI/CD Layer                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │               GitHub Actions Workflow                     │   │
│  ├──────────────────────────────────────────────────────────┤   │
│  │  1. Checkout Code                                        │   │
│  │  2. Terraform Plan                                       │   │
│  │  3. Run Checkov  ─────┐                                  │   │
│  │  4. Run Conftest      ├─→ FAIL? → Block PR              │   │
│  │  5. Run tfsec    ─────┘                                  │   │
│  │  6. Generate Report                                      │   │
│  │  7. Post Comment to PR                                   │   │
│  └──────────────────────────────────────────────────────────┘   │
│                              │                                    │
│                              ↓ PASS                               │
│                    ┌──────────────────┐                          │
│                    │  Terraform Apply │                          │
│                    └─────────┬────────┘                          │
└──────────────────────────────┼───────────────────────────────────┘
                               │
                               ↓
┌─────────────────────────────────────────────────────────────────┐
│                    Cloud Infrastructure                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌───────────────┐          ┌──────────────┐                    │
│  │  AWS Account  │          │  OpenStack   │                    │
│  ├───────────────┤          ├──────────────┤                    │
│  │ - EC2         │          │ - Instances  │                    │
│  │ - S3          │          │ - Volumes    │                    │
│  │ - RDS         │          │ - Networks   │                    │
│  │ - VPC         │          │ - Security   │                    │
│  └───────┬───────┘          └──────┬───────┘                    │
│          │                         │                             │
│          └─────────┬───────────────┘                             │
└────────────────────┼─────────────────────────────────────────────┘
                     │
                     ↓
┌─────────────────────────────────────────────────────────────────┐
│                   Runtime Scanning Layer                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌────────────────┐  ┌──────────────┐  ┌────────────────┐      │
│  │ InSpec Scanner │  │  ScoutSuite  │  │  OpenSCAP      │      │
│  ├────────────────┤  ├──────────────┤  ├────────────────┤      │
│  │ AWS CIS Profile│  │ Cloud Posture│  │ Linux Hardening│      │
│  │ Linux Profile  │  │ Assessment   │  │ Assessment     │      │
│  │ Custom Checks  │  │              │  │                │      │
│  └───────┬────────┘  └──────┬───────┘  └───────┬────────┘      │
│          │                  │                   │                │
│          └──────────────────┼───────────────────┘                │
│                             ↓                                     │
│                   ┌──────────────────┐                           │
│                   │ Results Collector│                           │
│                   │ (Normalizer)     │                           │
│                   └─────────┬────────┘                           │
└─────────────────────────────┼───────────────────────────────────┘
                              │
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                  Compliance Engine Layer                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              Compliance Decision Engine                   │   │
│  ├──────────────────────────────────────────────────────────┤   │
│  │  - Evaluate violations against severity                  │   │
│  │  - Check exceptions database                             │   │
│  │  - Determine remediation action                          │   │
│  │  - Generate alerts                                       │   │
│  └───────────────────────┬──────────────────────────────────┘   │
│                          │                                        │
│          ┌───────────────┼───────────────┐                       │
│          ↓               ↓               ↓                       │
│  ┌──────────────┐ ┌─────────────┐ ┌────────────┐               │
│  │ Auto-Remediate│ │    Alert    │ │   Ticket   │               │
│  ├──────────────┤ ├─────────────┤ ├────────────┤               │
│  │ Custodian    │ │ Slack/Email │ │ Jira/SNow  │               │
│  │ Lambda       │ │ PagerDuty   │ │            │               │
│  │ Ansible      │ │             │ │            │               │
│  └──────┬───────┘ └─────────────┘ └────────────┘               │
│         │                                                         │
└─────────┼─────────────────────────────────────────────────────────┘
          │
          ↓
┌─────────────────────────────────────────────────────────────────┐
│                   Evidence & Reporting Layer                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌──────────────┐     ┌────────────────┐     ┌──────────────┐  │
│  │ S3 Evidence  │     │ ELK Stack      │     │  Dashboards  │  │
│  │ Bucket       │ ──→ │ - Elasticsearch│ ──→ │  - Kibana    │  │
│  ├──────────────┤     │ - Logstash     │     │  - Grafana   │  │
│  │ Scan Reports │     │ - Kibana       │     │              │  │
│  │ Remediation  │     └────────────────┘     │ Compliance   │  │
│  │ Logs         │                            │ Score: 87%   │  │
│  │ Audit Trails │                            │              │  │
│  └──────────────┘                            └──────────────┘  │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Components

### 1. Pre-Deployment Validation

#### 1.1 Pre-commit Hooks
**Purpose**: Catch issues before code is committed
**Tools**:
- Checkov
- tfsec
- TFLint

**Configuration**: `.pre-commit-config.yaml`
```yaml
repos:
  - repo: https://github.com/antonbabenko/pre-commit-terraform
    hooks:
      - id: terraform_fmt
      - id: terraform_validate
      - id: terraform_tfsec
      - id: terraform_checkov
```

#### 1.2 CI/CD Pipeline Checks
**Purpose**: Gate pull requests and deployments
**Tools**:
- Checkov (comprehensive IaC scanning)
- Conftest (OPA policy validation)
- Custom validation scripts

**Workflow**: GitHub Actions
- Trigger: Pull request, push to main
- Blocking: Fail PR on critical violations
- Reporting: Post results as PR comment

#### 1.3 Conftest / OPA
**Purpose**: Custom policy enforcement
**Policy Language**: Rego
**Scope**: Terraform plans, CloudFormation templates

**Example Policy Location**: `policies/rego/`

### 2. Runtime Scanning

#### 2.1 InSpec
**Purpose**: Compliance validation against live resources
**Profiles**:
- `tests/inspec/aws-cis/` - AWS CIS Benchmark
- `tests/inspec/linux-cis/` - Linux CIS Benchmark

**Execution**:
- On-demand: Manual execution
- Scheduled: Daily/weekly scans via Lambda/cron
- Event-driven: Triggered by AWS Config changes

**Output**: JSON reports to S3

#### 2.2 OpenSCAP
**Purpose**: Linux image hardening validation
**Content**: SCAP Security Guide (SSG)
**Target**: EC2 AMIs, OpenStack images

**Integration**:
- Packer builds: Scan before publishing AMI
- Running instances: Scheduled scans

#### 2.3 ScoutSuite
**Purpose**: Multi-cloud security posture assessment
**Coverage**: AWS, Azure, GCP, OpenStack
**Frequency**: Weekly full scans

### 3. Enforcement & Remediation

#### 3.1 AWS Config Rules
**Purpose**: Continuous compliance monitoring
**Types**:
- Managed Rules: AWS-provided (e.g., `s3-bucket-public-read-prohibited`)
- Custom Rules: Lambda-based

**Remediation**: SSM Automation Documents

#### 3.2 Cloud Custodian
**Purpose**: Automated policy enforcement and remediation
**Policy Location**: `policies/custodian/`

**Example Use Cases**:
- Remove public S3 bucket access
- Stop non-compliant EC2 instances
- Delete unused security groups

**Execution**:
- Scheduled: Lambda cron
- Event-driven: CloudWatch Events

#### 3.3 Ansible Playbooks
**Purpose**: OpenStack and Linux remediation
**Playbook Location**: `remediation/ansible/`

**Example Use Cases**:
- Harden SSH configuration
- Configure auditd
- Apply security patches

### 4. Evidence & Reporting

#### 4.1 Evidence Collection
**Storage**: S3 bucket with versioning and object lock
**Retention**: 7 years (configurable per compliance requirement)

**Collected Data**:
- Scan reports (JSON)
- Remediation logs
- Exception approvals
- Audit trails

#### 4.2 Normalization Pipeline
**Purpose**: Convert diverse tool outputs to canonical schema

**Schema**:
```json
{
  "control_id": "CIS-AWS-2.1.1",
  "resource_id": "arn:aws:s3:::my-bucket",
  "provider": "aws",
  "resource_type": "s3_bucket",
  "finding": "Bucket allows HTTP access",
  "severity": "CRITICAL",
  "status": "FAIL",
  "found_at": "2025-12-07T10:30:00Z",
  "evidence": {...},
  "remediation_status": "auto_remediated",
  "remediation_timestamp": "2025-12-07T10:35:00Z"
}
```

#### 4.3 Dashboards
**Platform**: Kibana / Grafana
**Metrics**:
- Compliance score by standard (CIS, ISO, PCI)
- Trend over time
- Top violations
- Remediation SLA performance
- Coverage by control

---

## Data Flow

### 1. Pre-Deployment Flow

```
Developer writes Terraform → Commit → Pre-commit hook runs Checkov
                                            ↓
                                    PASS: Allow commit
                                    FAIL: Block commit, show errors
                                            ↓
                                    Fix issues → Retry commit
                                            ↓
                            Push to GitHub → GitHub Actions workflow
                                            ↓
                    Terraform Plan → Generate plan.json → Run Conftest
                                            ↓
                                    PASS: Allow merge
                                    FAIL: Block PR, post comment
                                            ↓
                            Merge → Terraform Apply → Deploy to AWS
```

### 2. Runtime Scanning Flow

```
Scheduled Trigger (Cron/Lambda) → Launch InSpec scan
                                            ↓
                        InSpec queries AWS APIs → Evaluate controls
                                            ↓
                        Generate JSON report → Upload to S3
                                            ↓
                        S3 Event → Lambda normalizer → Parse report
                                            ↓
                        Insert findings → Elasticsearch
                                            ↓
                Compliance Engine evaluates → Determine action
                                            ↓
        ┌───────────────┬───────────────┬──────────────┐
        ↓               ↓               ↓              ↓
  Auto-remediate     Alert           Ticket      Store evidence
  (Custodian)     (Slack/Email)     (Jira)         (S3)
```

### 3. Remediation Flow

```
Violation detected → Check exceptions database
                            ↓
                    No exception found
                            ↓
            Evaluate remediation policy (control config)
                            ↓
        ┌───────────────────┼───────────────────┐
        ↓                   ↓                   ↓
  auto_remediate      create_ticket        alert_only
        ↓                   ↓                   ↓
  Execute Custodian   Create Jira ticket   Send Slack alert
  or Ansible playbook                          ↓
        ↓                   ↓               Wait for manual
  Log action         Assign to team          remediation
        ↓                   ↓                   ↓
  Verify fix          Track SLA           Re-scan to verify
        ↓                   ↓                   ↓
  Update status      Close ticket         Update dashboard
```

---

## Integration Points

### 1. Version Control
- **GitHub/GitLab**: Source of truth for IaC
- **Branch Protection**: Require status checks to pass
- **PR Comments**: Automated compliance feedback

### 2. CI/CD
- **GitHub Actions / GitLab CI**: Primary pipeline
- **Status Checks**: Block merges on violations
- **Artifacts**: Store scan reports

### 3. Cloud Providers

#### AWS
- **IAM**: Roles for scanners and remediators
- **CloudTrail**: Audit all API calls
- **Config**: Continuous compliance monitoring
- **S3**: Evidence storage
- **Lambda**: Scheduled scans and remediations
- **EventBridge**: Event-driven triggers

#### OpenStack
- **Keystone**: Authentication
- **Nova/Neutron/Cinder**: Resource APIs
- **Policy Files**: RBAC enforcement

### 4. Notification Systems
- **Slack**: Real-time alerts
- **Email**: Digest reports
- **PagerDuty**: Critical violations

### 5. Ticketing
- **Jira**: Remediation tracking
- **ServiceNow**: Change management

---

## Security Considerations

### 1. Least Privilege
- Scanner roles: Read-only access
- Remediation roles: Specific write permissions (e.g., `s3:PutBucketPublicAccessBlock`)
- No permanent credentials in code

### 2. Secrets Management
- **HashiCorp Vault** or **AWS Secrets Manager**
- Rotate scanner credentials every 90 days
- Never commit credentials to Git

### 3. Evidence Integrity
- S3 bucket versioning enabled
- Object lock for immutability
- MFA delete protection
- CloudTrail logs on evidence bucket

### 4. Audit Trail
- All remediations logged with:
  - Who/what triggered
  - Before state
  - After state
  - Timestamp
  - Approval (if manual)

### 5. Network Security
- Scanners run in private subnets
- VPC endpoints for AWS APIs (no internet)
- Security groups with minimal ingress

---

## Scalability & Performance

### 1. Parallel Execution
- InSpec: Run multiple controls concurrently
- Custodian: Multi-region parallel scans
- CI/CD: Matrix builds for different environments

### 2. Incremental Scanning
- Only scan changed resources (via CloudTrail/Config)
- Cache previous scan results
- Differential reporting

### 3. Cost Optimization
- Use Lambda for scheduled scans (vs. always-on EC2)
- S3 lifecycle policies for evidence retention
- CloudWatch Logs retention policies

### 4. Performance Targets
- **IaC Scan**: < 2 minutes for typical Terraform module
- **Runtime Scan**: < 10 minutes for full AWS account
- **Remediation**: < 1 minute for automated fixes
- **Dashboard Refresh**: Real-time (< 30 seconds)

---

## Deployment Architecture

### Environments

```
┌──────────────┐      ┌──────────────┐      ┌──────────────┐
│ Development  │      │   Staging    │      │  Production  │
├──────────────┤      ├──────────────┤      ├──────────────┤
│ - Relaxed    │  →   │ - Enforced   │  →   │ - Strict     │
│   policies   │      │   (warning)  │      │   (blocking) │
│ - Fast tests │      │ - Full suite │      │ - Full suite │
│              │      │   + manual   │      │   + auto     │
│              │      │   remediation│      │   remediation│
└──────────────┘      └──────────────┘      └──────────────┘
```

### Multi-Account Strategy (AWS)

```
┌─────────────────────────────────────────────────────────┐
│                  AWS Organizations                       │
│                  (Management Account)                    │
├─────────────────────────────────────────────────────────┤
│  - SCPs (preventive controls)                           │
│  - CloudFormation StackSets                             │
│  - Centralized CloudTrail                               │
└───────────────────┬─────────────────────────────────────┘
                    │
        ┌───────────┼───────────┬───────────────┐
        ↓           ↓           ↓               ↓
┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
│ Security │  │   Dev    │  │ Staging  │  │   Prod   │
│ Tooling  │  │ Account  │  │ Account  │  │ Account  │
├──────────┤  ├──────────┤  ├──────────┤  ├──────────┤
│ InSpec   │  │ Workload │  │ Workload │  │ Workload │
│ Custodian│  │ Resources│  │ Resources│  │ Resources│
│ Evidence │  │          │  │          │  │          │
│ Bucket   │  └──────────┘  └──────────┘  └──────────┘
└──────────┘
     ↑
     └──── Cross-account scanning roles
```

---

## Technology Decisions

| Component | Technology | Rationale |
|-----------|------------|-----------|
| IaC | Terraform | Industry standard, multi-cloud |
| Policy Language | Rego (OPA) | Declarative, powerful, portable |
| Runtime Tests | InSpec | Ruby DSL, AWS/Azure/GCP support |
| Linux Scanning | OpenSCAP | NIST standard, comprehensive |
| Remediation | Custodian + Ansible | Cloud-native + config management |
| CI/CD | GitHub Actions | Integrated with GitHub, easy setup |
| Evidence Store | S3 + ELK | Durable, searchable, scalable |
| Dashboards | Kibana | Integrated with ELK, rich visualizations |

---

## Future Enhancements

1. **Machine Learning**: Predict violations before they occur
2. **Drift Detection**: Auto-PR to fix IaC when runtime drift detected
3. **Cost Optimization**: Link compliance with cost savings
4. **Multi-Region**: Replicate evidence across regions
5. **Blockchain**: Tamper-proof audit trails
6. **AI Assistant**: Natural language policy queries

---

**Document Version**: 1.0
**Last Updated**: 2025-12-07
**Maintained By**: Architecture Team
