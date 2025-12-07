# Compliance Control Mapping

This document maps compliance controls from various standards (CIS, ISO 27017, PCI-DSS) to automated checks, tests, and enforcement mechanisms.

## Table of Contents
- [Control Mapping Overview](#control-mapping-overview)
- [CIS AWS Foundations Benchmark](#cis-aws-foundations-benchmark)
- [CIS Linux Benchmark](#cis-linux-benchmark)
- [ISO 27017 Controls](#iso-27017-controls)
- [PCI-DSS Requirements](#pci-dss-requirements)
- [Mapping Schema](#mapping-schema)

## Control Mapping Overview

Each control is mapped to:
1. **IaC Check**: Pre-deployment validation (Checkov, OPA/Rego, tfsec)
2. **Runtime Check**: Live environment scanning (InSpec, OpenSCAP, ScoutSuite)
3. **Enforcement**: Blocking or remediation mechanism
4. **Evidence**: Logging and audit trail collection

### Severity Levels
- **CRITICAL**: Must block deployment, auto-remediate if possible
- **HIGH**: Should block deployment, requires review
- **MEDIUM**: Alert and create ticket
- **LOW**: Advisory only

---

## CIS AWS Foundations Benchmark

### Section 1: Identity and Access Management

| Control ID | Description | Severity | IaC Check | Runtime Check | Enforcement | Status |
|------------|-------------|----------|-----------|---------------|-------------|--------|
| **1.1** | Maintain current contact details | LOW | Manual | AWS Config | Advisory | 📋 Planned |
| **1.2** | Ensure security contact information is registered | MEDIUM | Manual | AWS Config | Advisory | 📋 Planned |
| **1.3** | Ensure security questions are registered in AWS account | LOW | Manual | AWS Config | Advisory | 📋 Planned |
| **1.4** | Ensure no 'root' user account access key exists | CRITICAL | N/A | InSpec: `aws_iam_root_user` | Block + Alert | ✅ Implemented |
| **1.5** | Ensure MFA is enabled for the 'root' user account | CRITICAL | N/A | InSpec: `aws_iam_root_user.has_mfa_enabled` | Block + Alert | ✅ Implemented |
| **1.6** | Ensure hardware MFA is enabled for the 'root' user account | HIGH | N/A | InSpec + AWS Config | Alert | 📋 Planned |
| **1.7** | Eliminate use of the 'root' user for administrative and daily tasks | MEDIUM | N/A | CloudTrail logs | Alert | 📋 Planned |
| **1.8** | Ensure IAM password policy requires minimum length of 14 or greater | HIGH | Checkov: CKV_AWS_9 | InSpec: `aws_iam_password_policy` | Block | ✅ Implemented |
| **1.9** | Ensure IAM password policy prevents password reuse | MEDIUM | Checkov: CKV_AWS_10 | InSpec | Alert | ✅ Implemented |
| **1.10** | Ensure multi-factor authentication (MFA) is enabled for all IAM users | HIGH | N/A | InSpec | Alert + Report | 📋 Planned |
| **1.11** | Do not setup access keys during initial user setup for all IAM users | MEDIUM | N/A | InSpec | Alert | 📋 Planned |
| **1.12** | Ensure credentials unused for 45 days or greater are disabled | MEDIUM | N/A | InSpec + Lambda | Auto-disable | 📋 Planned |
| **1.13** | Ensure there is only one active access key available for any single IAM user | MEDIUM | N/A | InSpec | Alert | 📋 Planned |
| **1.14** | Ensure access keys are rotated every 90 days or less | MEDIUM | N/A | InSpec | Alert | 📋 Planned |
| **1.15** | Ensure IAM Users Receive Permissions Only Through Groups | HIGH | Checkov: CKV_AWS_40 | InSpec | Alert | ✅ Implemented |
| **1.16** | Ensure IAM policies that allow full "*:*" administrative privileges are not attached | CRITICAL | OPA/Rego | InSpec | Block | ✅ Implemented |
| **1.17** | Ensure a support role has been created to manage incidents with AWS Support | MEDIUM | Terraform validation | AWS Config | Alert | 📋 Planned |
| **1.18** | Ensure IAM instance roles are used for AWS resource access from instances | HIGH | Checkov: CKV_AWS_117 | InSpec | Alert | ✅ Implemented |
| **1.19** | Ensure that all the expired SSL/TLS certificates stored in AWS IAM are removed | MEDIUM | N/A | InSpec | Alert | 📋 Planned |
| **1.20** | Ensure that IAM Access analyzer is enabled for all regions | HIGH | Checkov: CKV2_AWS_47 | AWS Config | Block | ✅ Implemented |
| **1.21** | Ensure IAM users are managed centrally via identity federation or AWS Organizations | MEDIUM | Manual | Manual | Advisory | 📋 Planned |

### Section 2: Storage

| Control ID | Description | Severity | IaC Check | Runtime Check | Enforcement | Status |
|------------|-------------|----------|-----------|---------------|-------------|--------|
| **2.1.1** | Ensure S3 Bucket Policy is set to deny HTTP requests | CRITICAL | Checkov: CKV_AWS_18 | InSpec: `aws_s3_bucket` | Block | ✅ Implemented |
| **2.1.2** | Ensure S3 buckets are encrypted at rest | CRITICAL | Checkov: CKV_AWS_19 | InSpec | Block + Remediate | ✅ Implemented |
| **2.1.3** | Ensure S3 bucket access logging is enabled on the CloudTrail bucket | HIGH | Checkov: CKV_AWS_20 | InSpec | Block | ✅ Implemented |
| **2.1.4** | Ensure that S3 Buckets are configured with 'Block public access' | CRITICAL | Checkov: CKV_AWS_21 | Custodian | Block + Remediate | ✅ Implemented |
| **2.1.5** | Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible | CRITICAL | Checkov: CKV_AWS_53 | InSpec | Block | ✅ Implemented |
| **2.2.1** | Ensure EBS volume encryption is enabled | CRITICAL | Checkov: CKV_AWS_3 | InSpec | Block + Remediate | ✅ Implemented |
| **2.2.2** | Ensure EBS volumes are attached to EC2 instances | MEDIUM | N/A | InSpec | Alert | 📋 Planned |
| **2.3.1** | Ensure that encryption is enabled for RDS instances | CRITICAL | Checkov: CKV_AWS_16 | InSpec | Block | ✅ Implemented |
| **2.3.2** | Ensure RDS DB instances prohibit public access | CRITICAL | Checkov: CKV_AWS_17 | InSpec + Custodian | Block + Remediate | ✅ Implemented |
| **2.3.3** | Ensure that public access is not given to RDS Instance | CRITICAL | OPA/Rego | InSpec | Block | ✅ Implemented |

### Section 3: Logging

| Control ID | Description | Severity | IaC Check | Runtime Check | Enforcement | Status |
|------------|-------------|----------|-----------|---------------|-------------|--------|
| **3.1** | Ensure CloudTrail is enabled in all regions | CRITICAL | Checkov: CKV_AWS_67 | InSpec: `aws_cloudtrail_trail` | Block | ✅ Implemented |
| **3.2** | Ensure CloudTrail log file validation is enabled | HIGH | Checkov: CKV_AWS_36 | InSpec | Block | ✅ Implemented |
| **3.3** | Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible | CRITICAL | Checkov: CKV_AWS_53 | InSpec | Block | ✅ Implemented |
| **3.4** | Ensure CloudTrail trails are integrated with CloudWatch Logs | HIGH | Checkov: CKV_AWS_35 | InSpec | Block | ✅ Implemented |
| **3.5** | Ensure AWS Config is enabled in all regions | HIGH | Checkov: CKV_AWS_38 | AWS Config | Block | ✅ Implemented |
| **3.6** | Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket | MEDIUM | Checkov: CKV_AWS_20 | InSpec | Alert | ✅ Implemented |
| **3.7** | Ensure CloudTrail logs are encrypted at rest using KMS CMKs | CRITICAL | Checkov: CKV_AWS_35 | InSpec | Block | ✅ Implemented |
| **3.8** | Ensure rotation for customer created symmetric CMKs is enabled | MEDIUM | Checkov: CKV_AWS_7 | InSpec | Alert | ✅ Implemented |
| **3.9** | Ensure VPC flow logging is enabled in all VPCs | HIGH | Checkov: CKV_AWS_76 | InSpec | Block | ✅ Implemented |
| **3.10** | Ensure that Object-level logging for write events is enabled for S3 bucket | MEDIUM | Terraform validation | AWS Config | Alert | 📋 Planned |
| **3.11** | Ensure that Object-level logging for read events is enabled for S3 bucket | MEDIUM | Terraform validation | AWS Config | Alert | 📋 Planned |

### Section 4: Monitoring

| Control ID | Description | Severity | IaC Check | Runtime Check | Enforcement | Status |
|------------|-------------|----------|-----------|---------------|-------------|--------|
| **4.1** | Ensure a log metric filter and alarm exist for unauthorized API calls | HIGH | N/A | AWS Config + Lambda | Alert | 📋 Planned |
| **4.2** | Ensure a log metric filter and alarm exist for Management Console sign-in without MFA | HIGH | N/A | CloudWatch Logs | Alert | 📋 Planned |
| **4.3** | Ensure a log metric filter and alarm exist for usage of 'root' account | CRITICAL | N/A | CloudWatch Logs | Alert | 📋 Planned |
| **4.4** | Ensure a log metric filter and alarm exist for IAM policy changes | HIGH | N/A | CloudWatch Logs | Alert | 📋 Planned |
| **4.5** | Ensure a log metric filter and alarm exist for CloudTrail configuration changes | HIGH | N/A | CloudWatch Logs | Alert | 📋 Planned |

### Section 5: Networking

| Control ID | Description | Severity | IaC Check | Runtime Check | Enforcement | Status |
|------------|-------------|----------|-----------|---------------|-------------|--------|
| **5.1** | Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports | CRITICAL | Checkov: CKV_AWS_229 | InSpec | Block | ✅ Implemented |
| **5.2** | Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports | CRITICAL | Checkov: CKV_AWS_24 | InSpec + Custodian | Block + Remediate | ✅ Implemented |
| **5.3** | Ensure the default security group of every VPC restricts all traffic | HIGH | Checkov: CKV_AWS_25 | InSpec | Block | ✅ Implemented |
| **5.4** | Ensure routing tables for VPC peering are "least access" | MEDIUM | OPA/Rego | InSpec | Alert | 📋 Planned |
| **5.5** | Ensure Network ACLs do not allow ingress from 0.0.0.0/0 to port 22 or port 3389 | CRITICAL | Checkov | InSpec | Block | ✅ Implemented |
| **5.6** | Ensure that EC2 Metadata Service only allows IMDSv2 | HIGH | Checkov: CKV_AWS_79 | InSpec | Block | ✅ Implemented |

---

## CIS Linux Benchmark

### Section 1: Initial Setup

| Control ID | Description | Severity | IaC Check | Runtime Check | Enforcement | Status |
|------------|-------------|----------|-----------|---------------|-------------|--------|
| **1.1.1.1** | Ensure mounting of cramfs filesystems is disabled | MEDIUM | Packer validation | OpenSCAP | Alert | 📋 Planned |
| **1.1.1.2** | Ensure mounting of freevxfs filesystems is disabled | MEDIUM | Packer validation | OpenSCAP | Alert | 📋 Planned |
| **1.1.1.3** | Ensure mounting of jffs2 filesystems is disabled | MEDIUM | Packer validation | OpenSCAP | Alert | 📋 Planned |
| **1.3.1** | Ensure AIDE is installed | HIGH | Packer validation | InSpec: `package('aide')` | Block | 📋 Planned |
| **1.4.1** | Ensure bootloader password is set | HIGH | N/A | InSpec | Alert | 📋 Planned |
| **1.5.1** | Ensure permissions on bootloader config are configured | HIGH | N/A | InSpec | Auto-remediate | 📋 Planned |

### Section 2: Services

| Control ID | Description | Severity | IaC Check | Runtime Check | Enforcement | Status |
|------------|-------------|----------|-----------|---------------|-------------|--------|
| **2.1.1** | Ensure xinetd is not installed | MEDIUM | Packer | InSpec: `package('xinetd')` | Alert | 📋 Planned |
| **2.2.2** | Ensure X Window System is not installed | MEDIUM | Packer | InSpec | Alert | 📋 Planned |
| **2.2.3** | Ensure Avahi Server is not installed | MEDIUM | Packer | InSpec | Alert | 📋 Planned |
| **2.3.1** | Ensure NIS Client is not installed | MEDIUM | Packer | InSpec | Alert | 📋 Planned |

### Section 3: Network Configuration

| Control ID | Description | Severity | IaC Check | Runtime Check | Enforcement | Status |
|------------|-------------|----------|-----------|---------------|-------------|--------|
| **3.1.1** | Disable IP forwarding | HIGH | N/A | InSpec: `kernel_parameter` | Auto-remediate | 📋 Planned |
| **3.1.2** | Ensure packet redirect sending is disabled | MEDIUM | N/A | InSpec | Auto-remediate | 📋 Planned |

### Section 4: Logging and Auditing

| Control ID | Description | Severity | IaC Check | Runtime Check | Enforcement | Status |
|------------|-------------|----------|-----------|---------------|-------------|--------|
| **4.1.1.1** | Ensure auditd is installed | HIGH | Packer | InSpec: `package('auditd')` | Block | 📋 Planned |
| **4.1.1.2** | Ensure auditd service is enabled | HIGH | N/A | InSpec: `service('auditd')` | Auto-remediate | 📋 Planned |
| **4.1.1.3** | Ensure auditing for processes that start prior to auditd is enabled | HIGH | N/A | InSpec | Alert | 📋 Planned |
| **4.2.1.1** | Ensure rsyslog is installed | HIGH | Packer | InSpec | Block | 📋 Planned |
| **4.2.1.2** | Ensure rsyslog Service is enabled | HIGH | N/A | InSpec | Auto-remediate | 📋 Planned |

### Section 5: Access, Authentication and Authorization

| Control ID | Description | Severity | IaC Check | Runtime Check | Enforcement | Status |
|------------|-------------|----------|-----------|---------------|-------------|--------|
| **5.1.1** | Ensure cron daemon is enabled | MEDIUM | N/A | InSpec: `service('cron')` | Auto-remediate | 📋 Planned |
| **5.2.1** | Ensure permissions on /etc/ssh/sshd_config are configured | HIGH | N/A | InSpec: `file('/etc/ssh/sshd_config')` | Auto-remediate | ✅ Implemented |
| **5.2.2** | Ensure SSH access is limited | HIGH | N/A | InSpec | Alert | 📋 Planned |
| **5.2.3** | Ensure permissions on SSH private host key files are configured | HIGH | N/A | InSpec | Auto-remediate | 📋 Planned |
| **5.2.4** | Ensure SSH Protocol is set to 2 | HIGH | N/A | InSpec | Auto-remediate | ✅ Implemented |
| **5.2.5** | Ensure SSH LogLevel is appropriate | MEDIUM | N/A | InSpec | Alert | ✅ Implemented |
| **5.2.8** | Ensure SSH root login is disabled | CRITICAL | N/A | InSpec | Auto-remediate | ✅ Implemented |
| **5.2.10** | Ensure SSH PermitUserEnvironment is disabled | MEDIUM | N/A | InSpec | Auto-remediate | ✅ Implemented |
| **5.3.1** | Ensure password creation requirements are configured | HIGH | N/A | InSpec | Alert | 📋 Planned |
| **5.3.2** | Ensure lockout for failed password attempts is configured | HIGH | N/A | InSpec | Alert | 📋 Planned |
| **5.3.3** | Ensure password reuse is limited | MEDIUM | N/A | InSpec | Alert | 📋 Planned |
| **5.4.1.1** | Ensure password expiration is 365 days or less | MEDIUM | N/A | InSpec | Alert | 📋 Planned |
| **5.4.1.4** | Ensure inactive password lock is 30 days or less | MEDIUM | N/A | InSpec | Alert | 📋 Planned |

### Section 6: System Maintenance

| Control ID | Description | Severity | IaC Check | Runtime Check | Enforcement | Status |
|------------|-------------|----------|-----------|---------------|-------------|--------|
| **6.1.2** | Ensure permissions on /etc/passwd are configured | HIGH | N/A | InSpec: `file('/etc/passwd')` | Auto-remediate | ✅ Implemented |
| **6.1.3** | Ensure permissions on /etc/shadow are configured | CRITICAL | N/A | InSpec: `file('/etc/shadow')` | Auto-remediate | ✅ Implemented |
| **6.1.4** | Ensure permissions on /etc/group are configured | HIGH | N/A | InSpec | Auto-remediate | ✅ Implemented |
| **6.2.1** | Ensure password fields are not empty | CRITICAL | N/A | InSpec | Alert | 📋 Planned |

---

## ISO 27017 Controls

ISO 27017 provides cloud-specific guidance extending ISO 27002. Key controls:

| Control ID | ISO 27017 Clause | Description | Severity | Implementation | Status |
|------------|------------------|-------------|----------|----------------|--------|
| **CLD.6.3.1** | Segregation in Networks | Logical network segregation between customers | CRITICAL | AWS VPC + Security Groups | ✅ Implemented |
| **CLD.9.5.1** | Shared Networks | Isolation on shared network infrastructure | HIGH | Network ACLs + VPC Peering controls | 📋 Planned |
| **CLD.9.5.2** | Virtual Network Security | Virtual network security controls | HIGH | Security Groups validation | ✅ Implemented |
| **CLD.10.1.1** | Data at Rest | Encryption of data at rest | CRITICAL | KMS encryption (S3, EBS, RDS) | ✅ Implemented |
| **CLD.10.1.2** | Data in Transit | Encryption of data in transit | CRITICAL | TLS/SSL enforcement | ✅ Implemented |
| **CLD.12.1.1** | Audit Logging | Comprehensive audit logging | HIGH | CloudTrail + Config | ✅ Implemented |
| **CLD.12.1.2** | Log Protection | Protection of audit logs | HIGH | S3 bucket policies + versioning | ✅ Implemented |
| **CLD.12.4.1** | Clock Sync | Synchronized time source for logging | MEDIUM | NTP configuration | 📋 Planned |
| **CLD.13.1.1** | Asset Inventory | Maintain cloud asset inventory | MEDIUM | AWS Config + Tagging | 📋 Planned |

---

## PCI-DSS Requirements

PCI-DSS v4.0 requirements relevant to cloud infrastructure:

| Requirement | Description | Severity | Implementation | Status |
|-------------|-------------|----------|----------------|--------|
| **1.2.1** | Restrict inbound and outbound traffic | CRITICAL | Security Groups + NACLs validation | ✅ Implemented |
| **1.3.1** | DMZ implementation | HIGH | VPC subnet design validation | 📋 Planned |
| **2.2.1** | Configuration standards for servers | HIGH | CIS Benchmark compliance | ✅ Implemented |
| **2.2.2** | Enable only necessary services | HIGH | Port/service validation | 📋 Planned |
| **2.2.3** | Implement additional security features | HIGH | Security hardening checks | 📋 Planned |
| **2.2.5** | Manage vendor defaults | HIGH | Default password checks | 📋 Planned |
| **3.4.1** | Render PAN unreadable | CRITICAL | Encryption at rest (KMS) | ✅ Implemented |
| **3.5.1** | Protect cryptographic keys | CRITICAL | KMS key policies | ✅ Implemented |
| **4.1.1** | Encrypt transmission of cardholder data | CRITICAL | TLS/SSL enforcement | ✅ Implemented |
| **8.2.1** | Strong authentication | CRITICAL | MFA enforcement | ✅ Implemented |
| **8.2.4** | Change passwords every 90 days | MEDIUM | IAM password policy | ✅ Implemented |
| **8.3.1** | MFA for all remote access | CRITICAL | IAM MFA checks | ✅ Implemented |
| **10.2.1** | Audit trail for all access | HIGH | CloudTrail validation | ✅ Implemented |
| **10.3.1** | Audit trail includes user ID | HIGH | CloudTrail configuration | ✅ Implemented |
| **10.5.1** | Protect audit trails | HIGH | S3 bucket protection | ✅ Implemented |
| **10.6.1** | Review logs daily | MEDIUM | CloudWatch Alarms | 📋 Planned |
| **11.3.1** | Quarterly external penetration testing | MEDIUM | Manual process | 📋 Planned |
| **12.3.1** | Usage policies for critical technologies | LOW | Documentation | 📋 Planned |

---

## Mapping Schema

### Control Definition Format

Each control follows this schema:

```yaml
control:
  id: "CIS-AWS-1.4"
  standard: "CIS AWS Foundations Benchmark v1.5.0"
  section: "1. Identity and Access Management"
  title: "Ensure no 'root' user account access key exists"
  description: "The root user is the most privileged user in an AWS account..."
  severity: "CRITICAL"

  iac_checks:
    - tool: "N/A"
      reason: "Root user is not managed via IaC"

  runtime_checks:
    - tool: "InSpec"
      profile: "aws-cis"
      control: "cis-aws-1-4"
      resource: "aws_iam_root_user"
      check: "should_not have_access_key"

    - tool: "AWS Config"
      rule: "iam-root-access-key-check"
      managed: true

  enforcement:
    mode: "block"
    actions:
      - type: "alert"
        channel: "slack"
        severity: "critical"
      - type: "ticket"
        system: "jira"
        priority: "P1"

  remediation:
    automated: false
    manual_steps:
      - "Login to AWS Console as root"
      - "Navigate to IAM → Users → root"
      - "Delete access keys"

  evidence:
    - type: "inspec_report"
      format: "json"
      retention: "365 days"
    - type: "aws_config_snapshot"
      format: "json"
      retention: "365 days"

  references:
    - "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html"
    - "CIS AWS Foundations Benchmark v1.5.0, Control 1.4"

  exceptions:
    allowed: false
    max_duration: null
```

### Implementation Priority

**Phase 1 (Foundation):**
- Critical severity controls
- High-impact, easy-to-implement checks
- S3, IAM, CloudTrail basics

**Phase 2 (Expansion):**
- High severity controls
- Networking controls
- Linux hardening

**Phase 3 (Advanced):**
- Medium/Low severity controls
- Advanced monitoring
- Complex remediations

---

## Coverage Summary

### Current Implementation Status

| Standard | Total Controls | Implemented | In Progress | Planned | Coverage % |
|----------|----------------|-------------|-------------|---------|------------|
| CIS AWS Foundations | 60 | 32 | 8 | 20 | 53% |
| CIS Linux | 95 | 12 | 5 | 78 | 13% |
| ISO 27017 | 40 | 8 | 4 | 28 | 20% |
| PCI-DSS | 35 | 12 | 3 | 20 | 34% |
| **TOTAL** | **230** | **64** | **20** | **146** | **28%** |

### By Severity

| Severity | Total | Implemented | Coverage % |
|----------|-------|-------------|------------|
| CRITICAL | 42 | 28 | 67% |
| HIGH | 78 | 24 | 31% |
| MEDIUM | 85 | 10 | 12% |
| LOW | 25 | 2 | 8% |

---

## Maintenance

This mapping document is maintained alongside:
- `/config/controls/` - YAML definitions of each control
- `/config/mappings/` - Machine-readable mapping files
- `/policies/` - Actual policy implementations
- `/tests/` - Test suite implementations

**Last Updated**: 2025-12-07
**Next Review**: Quarterly
**Owner**: Compliance Team
