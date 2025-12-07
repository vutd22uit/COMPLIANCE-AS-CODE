# CIS Benchmark Compliance Framework - Project Focus

## Overview

This project focuses **exclusively on CIS (Center for Internet Security) Benchmark compliance** for cloud infrastructure and Linux systems.

## Scope

### ✅ IN SCOPE: CIS Benchmarks

1. **CIS AWS Foundations Benchmark v1.5.0**
   - 60 controls across 5 sections
   - Coverage: IAM, Storage, Logging, Monitoring, Networking

2. **CIS Linux Benchmark (Ubuntu/RHEL/Amazon Linux)**
   - 95+ controls for OS hardening
   - Coverage: System configuration, Services, Network, Logging, Access control

### ❌ OUT OF SCOPE

- ISO 27017 (Cloud-specific controls)
- PCI-DSS (Payment card industry)
- HIPAA (Healthcare)
- SOC 2
- NIST frameworks
- Custom organizational policies

## Why CIS Benchmark Only?

### 1. **Industry Standard**
- Most widely adopted security baseline
- Free and publicly available
- Maintained by security experts worldwide

### 2. **Comprehensive Coverage**
- Covers 80% of common security misconfigurations
- Battle-tested in production environments
- Regular updates and improvements

### 3. **Tool Support**
- Extensive tooling ecosystem (InSpec, Checkov, OpenSCAP)
- Pre-built profiles and policies
- Community support

### 4. **Audit & Compliance**
- Accepted by auditors globally
- Maps to other frameworks (NIST, ISO, etc.)
- Evidence-friendly

### 5. **Practical & Actionable**
- Clear pass/fail criteria
- Specific remediation steps
- Low false-positive rate

## CIS Benchmark Structure

### CIS AWS Foundations Benchmark v1.5.0

```
Section 1: Identity and Access Management (IAM)
├── 1.1 - 1.3: Account Configuration
├── 1.4 - 1.7: Root Account Protection
├── 1.8 - 1.14: Password & Credential Management
├── 1.15 - 1.18: IAM Policies & Roles
└── 1.19 - 1.21: Certificate & Federation

Section 2: Storage
├── 2.1.1 - 2.1.5: S3 Bucket Security
├── 2.2.1 - 2.2.2: EBS Volume Encryption
└── 2.3.1 - 2.3.3: RDS Security

Section 3: Logging
├── 3.1 - 3.9: CloudTrail Configuration
├── 3.10 - 3.11: S3 Object Logging
└── 3.12: VPC Flow Logs

Section 4: Monitoring
├── 4.1 - 4.16: CloudWatch Alarms
└── Metric Filters for Security Events

Section 5: Networking
├── 5.1 - 5.3: VPC & Security Group Configuration
├── 5.4: Route Table Least Privilege
└── 5.5 - 5.6: Network Access Control
```

### CIS Linux Benchmark (Example: Ubuntu 22.04)

```
Section 1: Initial Setup
├── 1.1: Filesystem Configuration
├── 1.2: Software Updates
├── 1.3: Filesystem Integrity
├── 1.4: Bootloader Security
└── 1.5: Additional Process Hardening

Section 2: Services
├── 2.1: Special Purpose Services
├── 2.2: Service Clients
└── 2.3: Time Synchronization

Section 3: Network Configuration
├── 3.1: Network Parameters (Host Only)
├── 3.2: Network Parameters (Host and Router)
├── 3.3: IPv6
└── 3.4: TCP Wrappers

Section 4: Logging and Auditing
├── 4.1: Configure System Accounting (auditd)
└── 4.2: Configure Logging

Section 5: Access, Authentication and Authorization
├── 5.1: Configure cron
├── 5.2: SSH Server Configuration
├── 5.3: Configure PAM
└── 5.4: User Accounts and Environment

Section 6: System Maintenance
├── 6.1: System File Permissions
└── 6.2: User and Group Settings
```

## Implementation Priorities

### Phase 1: CRITICAL Controls (Priority 1)

These controls address the most severe security risks:

**AWS:**
- CIS-AWS-1.4: No root access keys
- CIS-AWS-1.5: Root account MFA
- CIS-AWS-1.16: No full admin policies
- CIS-AWS-2.1.2: S3 encryption
- CIS-AWS-2.1.4: Block S3 public access
- CIS-AWS-3.1: CloudTrail enabled
- CIS-AWS-5.2: No open security groups

**Linux:**
- CIS-LINUX-5.2.8: SSH root login disabled
- CIS-LINUX-6.1.3: /etc/shadow permissions
- CIS-LINUX-6.2.1: No empty passwords

**Total: ~40 CRITICAL controls**
**Target: Week 1-4**

### Phase 2: HIGH Controls (Priority 2)

Important security controls:

**AWS:**
- Password policies
- MFA enforcement
- CloudTrail log encryption
- VPC flow logging
- IAM Access Analyzer

**Linux:**
- auditd configuration
- SSH hardening
- File permissions
- Service hardening

**Total: ~80 HIGH controls**
**Target: Week 5-8**

### Phase 3: MEDIUM/LOW Controls (Priority 3)

Best practices and defense-in-depth:

**AWS:**
- Tag enforcement
- Support role creation
- Certificate expiration

**Linux:**
- Additional hardening
- Legacy service removal
- Kernel parameter tuning

**Total: ~135 MEDIUM/LOW controls**
**Target: Week 9-14**

## Control Implementation Matrix

| Control Level | Pre-Deploy Check | Runtime Scan | Auto-Remediate | Manual Review |
|---------------|------------------|--------------|----------------|---------------|
| **CRITICAL** | ✅ Block PR | ✅ Hourly | ✅ Immediate | ❌ None |
| **HIGH** | ✅ Block PR | ✅ Daily | ⚠️ With approval | ✅ SLA: 24h |
| **MEDIUM** | ⚠️ Warning | ✅ Weekly | ❌ No | ✅ SLA: 7d |
| **LOW** | ℹ️ Info | ✅ Monthly | ❌ No | ✅ SLA: 30d |

## Tooling Mapping

### Pre-Deployment (IaC Scanning)

```
Terraform/CloudFormation Code
    ↓
┌─────────────────────────────────┐
│ Checkov (AWS CIS checks)        │ ← 45+ built-in CIS checks
├─────────────────────────────────┤
│ tfsec (AWS security)            │ ← 30+ CIS-related checks
├─────────────────────────────────┤
│ OPA/Conftest (Custom policies)  │ ← Custom CIS logic
└─────────────────────────────────┘
    ↓
Quality Gate (Pass/Fail)
```

### Runtime Scanning

```
AWS Account / Linux Instances
    ↓
┌─────────────────────────────────┐
│ InSpec (CIS Profiles)           │
│  - aws-cis-benchmark            │ ← Official CIS profile
│  - linux-baseline               │ ← DevSec hardening
│  - cis-aws-foundations-baseline │ ← Community profile
├─────────────────────────────────┤
│ OpenSCAP (Linux)                │
│  - SCAP Security Guide          │ ← Official CIS content
│  - CIS benchmarks               │
├─────────────────────────────────┤
│ AWS Config Rules                │
│  - Managed rules (CIS-aligned)  │ ← AWS-provided
└─────────────────────────────────┘
    ↓
Compliance Dashboard
```

### Remediation

```
Violations Detected
    ↓
┌─────────────────────────────────┐
│ Cloud Custodian                 │
│  - S3 public block              │
│  - EBS encryption               │
│  - Security group cleanup       │
├─────────────────────────────────┤
│ AWS Config Remediation          │
│  - SSM Automation documents     │
│  - Native AWS remediation       │
├─────────────────────────────────┤
│ Ansible (Linux hardening)       │
│  - SSH configuration            │
│  - File permissions             │
│  - Package management           │
└─────────────────────────────────┘
    ↓
Verification Scan
```

## Success Metrics

### Compliance Score Calculation

```python
compliance_score = (passed_controls / total_controls) * 100

# Weighted by severity
weighted_score = (
    (critical_passed * 4) +
    (high_passed * 3) +
    (medium_passed * 2) +
    (low_passed * 1)
) / (
    (total_critical * 4) +
    (total_high * 3) +
    (total_medium * 2) +
    (total_low * 1)
) * 100
```

### Target KPIs

| Metric | Current | Target | Timeline |
|--------|---------|--------|----------|
| **Overall Compliance** | 28% | 90% | Week 12 |
| **CRITICAL Compliance** | 67% | 100% | Week 4 |
| **HIGH Compliance** | 31% | 95% | Week 8 |
| **MEDIUM Compliance** | 12% | 85% | Week 12 |
| **Mean Time to Detect (MTTD)** | N/A | < 1 hour | Week 6 |
| **Mean Time to Remediate (MTTR)** | N/A | < 4 hours | Week 10 |
| **False Positive Rate** | N/A | < 5% | Week 8 |
| **Auto-Remediation Rate** | 0% | 70% | Week 12 |

## Evidence & Audit Trail

### What We Store

For each CIS control, we maintain:

1. **Scan Results** (Raw)
   - InSpec JSON output
   - OpenSCAP XCCDF results
   - Checkov JSON reports

2. **Normalized Findings**
   ```json
   {
     "control_id": "CIS-AWS-2.1.4",
     "control_title": "Ensure S3 buckets have block public access",
     "resource_id": "arn:aws:s3:::my-bucket",
     "status": "FAIL",
     "severity": "CRITICAL",
     "timestamp": "2025-12-07T10:30:00Z",
     "evidence": {
       "block_public_acls": false,
       "block_public_policy": false,
       "ignore_public_acls": false,
       "restrict_public_buckets": false
     },
     "remediation_available": true
   }
   ```

3. **Remediation Logs**
   ```json
   {
     "remediation_id": "rem-abc123",
     "control_id": "CIS-AWS-2.1.4",
     "resource_id": "arn:aws:s3:::my-bucket",
     "triggered_at": "2025-12-07T10:31:00Z",
     "completed_at": "2025-12-07T10:31:15Z",
     "method": "cloud-custodian",
     "before_state": {...},
     "after_state": {...},
     "success": true
   }
   ```

4. **Compliance Snapshots** (Daily)
   - Overall compliance score
   - Per-section scores
   - Trend data

### Retention Policy

| Data Type | Retention | Storage Class | Encryption |
|-----------|-----------|---------------|------------|
| Raw scan results | 7 years | S3 Glacier | KMS |
| Normalized findings | 3 years | S3 Standard | KMS |
| Remediation logs | 7 years | S3 Glacier | KMS |
| Daily snapshots | 1 year | S3 Standard-IA | KMS |
| Dashboard data | 90 days | Elasticsearch | At-rest |

## Reference Materials

### Official CIS Benchmarks

1. **CIS AWS Foundations Benchmark v1.5.0**
   - URL: https://www.cisecurity.org/benchmark/amazon_web_services
   - PDF: 200+ pages
   - Last Updated: 2023-08

2. **CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0**
   - URL: https://www.cisecurity.org/benchmark/ubuntu_linux
   - PDF: 800+ pages
   - Last Updated: 2023-10

3. **CIS Red Hat Enterprise Linux 8 Benchmark v3.0.0**
   - URL: https://www.cisecurity.org/benchmark/red_hat_linux
   - PDF: 900+ pages
   - Last Updated: 2023-12

### InSpec Profiles

1. **AWS CIS Benchmark Profile**
   - Repo: https://github.com/mitre/aws-foundations-cis-baseline
   - Controls: 60
   - Maintained by: MITRE

2. **Linux Baseline**
   - Repo: https://github.com/dev-sec/linux-baseline
   - Controls: 50+
   - Maintained by: DevSec Hardening Framework

3. **CIS Docker Benchmark**
   - Repo: https://github.com/dev-sec/cis-docker-benchmark
   - Controls: 100+
   - Maintained by: DevSec

### Tools & Resources

- **Checkov**: https://www.checkov.io/
- **InSpec**: https://docs.chef.io/inspec/
- **OpenSCAP**: https://www.open-scap.org/
- **Cloud Custodian**: https://cloudcustodian.io/
- **AWS Config**: https://aws.amazon.com/config/

## FAQ

### Q: Why not include ISO 27017 or PCI-DSS?

**A:** Focus and scope management. CIS Benchmark alone provides:
- 155 controls (60 AWS + 95 Linux)
- Sufficient coverage for most security needs
- Clear, unambiguous requirements
- Better tool support

Adding more frameworks would:
- Increase complexity 3-4x
- Create overlapping controls
- Dilute focus and quality
- Extend timeline significantly

### Q: Can we map CIS to other frameworks later?

**A:** Yes! CIS controls map to:
- NIST CSF (90% overlap)
- ISO 27001/27017 (70% overlap)
- PCI-DSS (60% overlap)
- SOC 2 (80% overlap)

Once CIS is implemented, mapping to other frameworks is straightforward.

### Q: What about custom organizational policies?

**A:** After CIS baseline is established (Week 12), we can:
- Add custom controls using the same framework
- Extend InSpec profiles
- Add custom Rego policies
- Layer additional requirements

The framework is extensible.

### Q: Why both AWS and Linux CIS?

**A:** Complete coverage:
- **CIS AWS**: Cloud infrastructure layer
- **CIS Linux**: Operating system layer (EC2, containers)

Both are needed for defense-in-depth.

---

## Next Steps

1. **Review this document** with stakeholders
2. **Prioritize controls** based on risk assessment
3. **Assign ownership** for each control section
4. **Begin Phase 1** implementation (CRITICAL controls)
5. **Track progress** weekly against KPIs

---

**Document Version**: 1.0
**Last Updated**: 2025-12-07
**Focus**: CIS Benchmark Only (AWS + Linux)
**Out of Scope**: ISO 27017, PCI-DSS, HIPAA, SOC 2, NIST
