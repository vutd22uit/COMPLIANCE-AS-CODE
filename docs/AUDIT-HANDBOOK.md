# Audit Handbook - CIS Benchmark Compliance Evidence

## Purpose

This handbook guides auditors through the compliance evidence collection system for CIS Benchmark controls on AWS and Linux systems.

---

## Table of Contents

- [Overview](#overview)
- [Evidence Types](#evidence-types)
- [Evidence Storage](#evidence-storage)
- [Accessing Evidence](#accessing-evidence)
- [Verifying Evidence](#verifying-evidence)
- [Sample Audit Workflows](#sample-audit-workflows)
- [Evidence Retention](#evidence-retention)
- [Contact Information](#contact-information)

---

## Overview

### Compliance Framework

This organization implements **CIS (Center for Internet Security) Benchmarks** for:

- **CIS AWS Foundations Benchmark v1.5.0** (60 controls)
- **CIS Linux Benchmark** (95+ controls for Ubuntu/RHEL/Amazon Linux)

**Total**: 155 controls

### Compliance Approach

**Three-layer enforcement**:

1. **Pre-deployment**: IaC scanning (Checkov, tfsec, OPA) blocks non-compliant code
2. **Runtime**: Continuous scanning (InSpec hourly for CRITICAL, daily for HIGH)
3. **Remediation**: Automatic fixes for safe controls, alerts for others

### Evidence Collection

**All evidence is**:
- ✅ **Immutable**: S3 object lock prevents deletion/modification
- ✅ **Versioned**: Full version history maintained
- ✅ **Encrypted**: KMS encryption at rest
- ✅ **Timestamped**: UTC timestamps with millisecond precision
- ✅ **Hash-verified**: SHA-256 integrity checks
- ✅ **Retained**: 7 years for audit compliance

---

## Evidence Types

### 1. Scan Results (Raw)

**What**: Original scanner output (InSpec JSON, Checkov JSON)
**Why**: Unaltered evidence from scanning tools
**Location**: `s3://evidence/raw-scans/`
**Format**: JSON
**Retention**: 7 years

**Example**:
```
s3://compliance-evidence-123456789012/raw-scans/inspec/2025/12/07/inspec-aws-cis-2025-12-07-10-30-00.json
```

**Contents**:
- Scanner metadata (version, runtime)
- All controls executed
- Pass/Fail results with evidence
- Timestamps
- SHA-256 hash

### 2. Normalized Findings

**What**: Standardized format across all scanners
**Why**: Consistent queryable format
**Location**: `s3://evidence/normalized-findings/`
**Format**: NDJSON (newline-delimited JSON)
**Retention**: 3 years

**Schema**:
```json
{
  "finding_id": "unique-id",
  "control": {"id": "CIS-AWS-2.1.4", "title": "..."},
  "severity": "CRITICAL",
  "status": "FAIL",
  "resource": {"id": "arn:aws:...", "type": "s3_bucket"},
  "evidence": {"actual_value": {...}, "expected_value": {...}},
  "timestamp": "2025-12-07T10:30:15Z"
}
```

### 3. Remediation Logs

**What**: Audit trail of all fixes
**Why**: Proof of corrective action
**Location**: `s3://evidence/remediations/`
**Format**: JSON
**Retention**: 7 years

**Contents**:
- **Before state**: What was wrong
- **After state**: What was fixed
- **Timeline**: Detection → Fix → Verification
- **Actor**: Who/what triggered remediation
- **Method**: Cloud Custodian / Ansible / Manual
- **Verification**: Re-scan proof of fix

### 4. Compliance Snapshots

**What**: Point-in-time compliance state
**Why**: Track compliance trends
**Location**: `s3://evidence/snapshots/`
**Frequency**: Daily, Weekly, Monthly
**Retention**: 1 year

**Contents**:
- Overall compliance score
- By severity (CRITICAL, HIGH, MEDIUM, LOW)
- By standard (CIS AWS, CIS Linux)
- Top violations
- Trend vs. previous period

### 5. Audit Trail

**What**: Every action taken
**Why**: Chain of custody
**Location**: `s3://evidence/audit-trail/`
**Format**: NDJSON
**Retention**: 7 years

**Logged Events**:
- Scan execution
- Remediation triggered
- Exception granted
- Manual changes
- Report generation

---

## Evidence Storage

### S3 Bucket Structure

```
s3://compliance-evidence-123456789012/
├── raw-scans/
│   ├── inspec/
│   │   └── YYYY/MM/DD/inspec-aws-cis-YYYY-MM-DD-HH-MM-SS.json
│   ├── checkov/
│   └── scoutsuite/
│
├── normalized-findings/
│   └── YYYY/MM/DD/findings-YYYY-MM-DD-HH-MM.ndjson
│
├── remediations/
│   └── YYYY/MM/DD/rem-YYYYMMDD-HHMMSS-xxxxx.json
│
├── snapshots/
│   ├── daily/YYYY/MM/snap-YYYY-MM-DD-daily.json
│   ├── weekly/YYYY/MM/snap-YYYY-MM-DD-weekly.json
│   └── monthly/YYYY/snap-YYYY-MM-monthly.json
│
├── audit-trail/
│   └── YYYY/MM/DD/audit-YYYY-MM-DD-HH.ndjson
│
└── reports/
    ├── daily/YYYY/MM/compliance-report-YYYY-MM-DD.pdf
    ├── weekly/YYYY/MM/compliance-report-YYYY-week-WW.pdf
    └── monthly/YYYY/compliance-report-YYYY-MM.pdf
```

### Bucket Configuration

| Feature | Configuration | Purpose |
|---------|---------------|---------|
| **Versioning** | Enabled | Track all changes |
| **Object Lock** | GOVERNANCE mode, 7 years | Immutability |
| **Encryption** | KMS (aws:kms) | Data protection |
| **Lifecycle** | Standard → IA (90d) → Glacier (365d) | Cost optimization |
| **Access Logging** | Enabled | Audit access |
| **Public Access** | All blocked | Security |

---

## Accessing Evidence

### Prerequisites

**For auditors, you need**:
1. AWS IAM user with `ReadOnlyAccess` to evidence bucket
2. AWS CLI configured
3. (Optional) jq for JSON parsing

### Accessing via AWS Console

1. Login to AWS Console
2. Navigate to S3 service
3. Open bucket: `compliance-evidence-123456789012`
4. Browse folders by date
5. Download files directly

### Accessing via AWS CLI

```bash
# Configure AWS credentials
aws configure

# List scans for a specific date
aws s3 ls s3://compliance-evidence-123456789012/raw-scans/inspec/2025/12/07/

# Download specific scan
aws s3 cp s3://compliance-evidence-123456789012/raw-scans/inspec/2025/12/07/inspec-aws-cis-2025-12-07-10-30-00.json ./

# View compliance snapshot
aws s3 cp s3://compliance-evidence-123456789012/snapshots/daily/2025/12/snap-2025-12-07-daily.json - | jq .

# Search for findings for specific control
aws s3 cp s3://compliance-evidence-123456789012/normalized-findings/2025/12/07/findings.ndjson - | \
  jq -r 'select(.control.id == "CIS-AWS-2.1.4")'

# Get remediations for a specific resource
aws s3 ls s3://compliance-evidence-123456789012/remediations/2025/12/ --recursive | \
  while read -r line; do
    file=$(echo $line | awk '{print $4}')
    aws s3 cp "s3://compliance-evidence-123456789012/$file" - | jq 'select(.resource.id == "arn:aws:s3:::my-bucket")'
  done
```

### Query Examples

#### 1. Get all CRITICAL failures for a date

```bash
aws s3 cp s3://compliance-evidence-123456789012/normalized-findings/2025/12/07/findings.ndjson - | \
  jq -r 'select(.severity == "CRITICAL" and .status == "FAIL") |
         {control: .control.id, resource: .resource.id, evidence: .evidence}'
```

#### 2. Calculate compliance score from snapshot

```bash
aws s3 cp s3://compliance-evidence-123456789012/snapshots/daily/2025/12/snap-2025-12-07-daily.json - | \
  jq '.overall.compliance_score'
```

#### 3. Get remediation success rate

```bash
aws s3 ls s3://compliance-evidence-123456789012/remediations/2025/12/ --recursive | \
  while read -r line; do
    file=$(echo $line | awk '{print $4}')
    aws s3 cp "s3://compliance-evidence-123456789012/$file" - | jq -r '.outcome.success'
  done | \
  awk '{success+=$1; total++} END {print "Success Rate: " (success/total*100) "%"}'
```

---

## Verifying Evidence

### Evidence Integrity

Every evidence file includes:

1. **SHA-256 Hash**: Verify file integrity
2. **Timestamp**: When evidence was collected
3. **Scanner Version**: Tool version used
4. **Digital Signature** (for critical evidence): Cryptographic proof

### Verification Steps

#### 1. Verify SHA-256 Hash

```bash
# Download evidence file
aws s3 cp s3://evidence-bucket/raw-scans/inspec/2025/12/07/scan.json ./scan.json

# Extract embedded hash
EMBEDDED_HASH=$(jq -r '.sha256' scan.json)

# Calculate actual hash (excluding the hash field itself)
ACTUAL_HASH=$(jq 'del(.sha256)' scan.json | shasum -a 256 | awk '{print $1}')

# Compare
if [ "$EMBEDDED_HASH" == "$ACTUAL_HASH" ]; then
  echo "✅ Evidence integrity verified"
else
  echo "❌ Evidence may be tampered"
fi
```

#### 2. Verify Object Lock (Immutability)

```bash
# Check if object is locked
aws s3api get-object-retention \
  --bucket compliance-evidence-123456789012 \
  --key raw-scans/inspec/2025/12/07/scan.json

# Output shows retention mode and retain-until date
```

#### 3. Verify Chain of Custody

```bash
# Get object metadata
aws s3api head-object \
  --bucket compliance-evidence-123456789012 \
  --key raw-scans/inspec/2025/12/07/scan.json

# Check version history
aws s3api list-object-versions \
  --bucket compliance-evidence-123456789012 \
  --prefix raw-scans/inspec/2025/12/07/scan.json
```

---

## Sample Audit Workflows

### Workflow 1: Audit Specific Control (e.g., CIS-AWS-2.1.4)

**Objective**: Verify compliance with S3 public access block control

**Steps**:

1. **Review Control Definition**
   ```bash
   cat config/controls/CIS-AWS-2.1.4.yml
   ```

2. **Check Latest Scan Results**
   ```bash
   # Get latest scan for today
   LATEST=$(aws s3 ls s3://evidence/raw-scans/inspec/2025/12/07/ | tail -1 | awk '{print $4}')
   aws s3 cp s3://evidence/raw-scans/inspec/2025/12/07/$LATEST - | \
     jq '.controls[] | select(.tags.cis == "CIS-AWS-2.1.4")'
   ```

3. **Review Findings**
   ```bash
   aws s3 cp s3://evidence/normalized-findings/2025/12/07/findings.ndjson - | \
     jq -r 'select(.control.id == "CIS-AWS-2.1.4")'
   ```

4. **Check Remediation History**
   ```bash
   aws s3 ls s3://evidence/remediations/2025/12/ --recursive | \
     grep CIS-AWS-2.1.4
   ```

5. **Verify Current State** (optional - live verification)
   ```bash
   inspec exec tests/inspec/aws-cis --controls cis-aws-2-1-4 -t aws://
   ```

6. **Generate Audit Report**
   ```bash
   python evidence/reporters/compliance_reporter.py \
     --bucket evidence-bucket \
     --type audit \
     --control CIS-AWS-2.1.4 \
     --format markdown \
     --save
   ```

### Workflow 2: Monthly Compliance Review

**Objective**: Review overall compliance for December 2025

**Steps**:

1. **Get Monthly Snapshot**
   ```bash
   aws s3 cp s3://evidence/snapshots/monthly/2025/snap-2025-12-monthly.json - | jq .
   ```

2. **Review Trend**
   ```bash
   # Compare current month vs previous
   aws s3 cp s3://evidence/snapshots/monthly/2025/snap-2025-12-monthly.json - | \
     jq '{current: .overall.compliance_score, change: .trend.score_change}'
   ```

3. **Identify Top Issues**
   ```bash
   aws s3 cp s3://evidence/snapshots/monthly/2025/snap-2025-12-monthly.json - | \
     jq '.top_violations[] | {control: .control_id, affected: .affected_resources}'
   ```

4. **Review Remediation Effectiveness**
   ```bash
   aws s3 cp s3://evidence/snapshots/monthly/2025/snap-2025-12-monthly.json - | \
     jq '.remediation_metrics'
   ```

5. **Download PDF Report**
   ```bash
   aws s3 cp s3://evidence/reports/monthly/2025/compliance-report-2025-12.pdf ./
   ```

### Workflow 3: Exception Audit

**Objective**: Verify all exceptions are justified and time-bounded

**Steps**:

1. **List Active Exceptions**
   ```bash
   # Query findings with exceptions
   aws s3 cp s3://evidence/normalized-findings/2025/12/07/findings.ndjson - | \
     jq -r 'select(.metadata.exception_id != null)'
   ```

2. **Review Exception Details**
   ```bash
   # Check exception database (stored separately)
   # Contains: who granted, reason, expiration date
   ```

3. **Verify Expired Exceptions**
   ```bash
   # Ensure no findings have expired exceptions
   ```

### Workflow 4: Remediation Audit

**Objective**: Verify auto-remediation only runs for approved controls

**Steps**:

1. **List All Auto-Remediations**
   ```bash
   aws s3 ls s3://evidence/remediations/2025/12/ --recursive | \
     while read -r line; do
       file=$(echo $line | awk '{print $4}')
       aws s3 cp "s3://evidence/$file" - | \
         jq 'select(.remediation.triggered_by == "auto")'
     done
   ```

2. **Cross-Check Against Approved List**
   ```bash
   # Compare with config/controls/*.yml auto-remediation flags
   ```

3. **Review Failed Remediations**
   ```bash
   aws s3 ls s3://evidence/remediations/2025/12/ --recursive | \
     while read -r line; do
       file=$(echo $line | awk '{print $4}')
       aws s3 cp "s3://evidence/$file" - | \
         jq 'select(.outcome.success == false)'
     done
   ```

---

## Evidence Retention

| Evidence Type | Retention Period | Storage Class Progression |
|---------------|------------------|---------------------------|
| Raw Scans | 7 years | Standard (0-90d) → IA (90-365d) → Glacier (365d-2555d) |
| Normalized Findings | 3 years | Standard (0-180d) → IA (180-730d) → Glacier (730d-1095d) |
| Remediation Logs | 7 years | Standard (0-90d) → IA (90-365d) → Glacier (365d-2555d) |
| Audit Trail | 7 years | Standard (0-90d) → IA (90-365d) → Glacier (365d-2555d) |
| Snapshots | 1 year | Standard (all) |
| Reports | 7 years | Standard (0-90d) → IA (90-365d) → Glacier (365d-2555d) |

**Retention Justification**: 7 years aligns with most regulatory requirements (SOX, HIPAA, PCI-DSS).

---

## Contact Information

### For Evidence Access

**Security Team**: cloud-security@company.com
**Slack**: #cloud-security
**On-Call**: security-oncall@company.com

### For Technical Issues

**Platform Team**: platform@company.com
**Slack**: #platform-engineering

### Escalation

**CISO**: ciso@company.com
**VP Engineering**: vp-eng@company.com

---

## Appendix

### Compliance Score Calculation

```python
# Overall score
compliance_score = (passed_controls / total_controls) * 100

# Weighted score (by severity)
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

### SLA Targets

| Severity | Detection SLA | Remediation SLA | Target Compliance |
|----------|---------------|-----------------|-------------------|
| CRITICAL | < 1 hour | < 4 hours | 100% |
| HIGH | < 4 hours | < 24 hours | ≥ 95% |
| MEDIUM | < 24 hours | < 7 days | ≥ 85% |
| LOW | < 7 days | < 30 days | ≥ 70% |

---

**Handbook Version**: 1.0
**Last Updated**: 2025-12-07
**Next Review**: 2026-03-07
**Owner**: Cloud Security Team
