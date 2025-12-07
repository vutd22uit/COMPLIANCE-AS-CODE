# 📦 Evidence Collection System - Complete Guide

## 🎯 TổngQuan

**Evidence Collection System** là hệ thống **TỰ ĐỘNG THU THẬP, LƯU TRỮ VÀ BÁO CÁO MINH CHỨNG** cho compliance audit CIS Benchmark.

### 🔐 Đặc Điểm Quan Trọng

- ✅ **IMMUTABLE**: Không thể xóa/sửa (S3 Object Lock)
- ✅ **VERSIONED**: Lưu trữ toàn bộ lịch sử
- ✅ **ENCRYPTED**: KMS encryption at rest
- ✅ **TIMESTAMPED**: UTC với millisecond precision
- ✅ **HASH-VERIFIED**: SHA-256 integrity checks
- ✅ **7-YEAR RETENTION**: Tuân thủ yêu cầu audit

---

## 📁 Cấu Trúc Hệ Thống

```
evidence/
├── README.md                          # Hướng dẫn sử dụng
├── EVIDENCE-SCHEMA.md                 # Schema documentation đầy đủ
│
├── collectors/                        # Python scripts thu thập evidence
│   └── evidence_collector.py          # Main collector
│       ├── collect_inspec_scan()      # Thu thập InSpec results
│       ├── normalize_findings()       # Chuẩn hóa findings
│       ├── store_evidence()           # Upload lên S3
│       └── create_compliance_snapshot() # Tạo snapshot
│
├── reporters/                         # Report generators
│   └── compliance_reporter.py         # Main reporter
│       ├── generate_daily_report()    # Báo cáo hàng ngày
│       ├── generate_audit_report()    # Báo cáo audit
│       ├── generate_markdown_report() # Format markdown
│       └── save_report()              # Lưu vào S3
│
├── terraform/                         # Infrastructure as Code
│   └── evidence-bucket.tf             # S3 bucket setup
│       ├── S3 bucket với Object Lock
│       ├── KMS encryption key
│       ├── Lifecycle policies
│       ├── IAM roles (collector, auditor)
│       └── Bucket policies (security)
│
├── samples/                           # Sample data
│   ├── sample-inspec-scan.json        # Example InSpec output
│   ├── sample-checkov-scan.json       # Example Checkov output
│   └── sample-remediation.json        # Example remediation log
│
└── scripts/                           # Utility scripts
    ├── demo-evidence-flow.sh          # 🎬 DEMO COMPLETE FLOW
    ├── verify-integrity.sh            # Verify SHA-256 hashes
    └── generate-sample-data.py        # Generate test data
```

---

## 🔄 Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                     1. SCAN EXECUTION                            │
├─────────────────────────────────────────────────────────────────┤
│  InSpec → Query AWS APIs → Execute CIS controls → Generate JSON │
└────────────────────────────┬────────────────────────────────────┘
                             ↓
┌─────────────────────────────────────────────────────────────────┐
│                  2. EVIDENCE COLLECTION                          │
├─────────────────────────────────────────────────────────────────┤
│  evidence_collector.py                                           │
│  ├─ collect_inspec_scan()  → Load JSON                          │
│  ├─ Calculate SHA-256      → Integrity hash                     │
│  └─ Create evidence ID     → Unique identifier                  │
└────────────────────────────┬────────────────────────────────────┘
                             ↓
┌─────────────────────────────────────────────────────────────────┐
│                   3. NORMALIZATION                               │
├─────────────────────────────────────────────────────────────────┤
│  normalize_findings()                                            │
│  ├─ Map to canonical schema                                     │
│  ├─ Extract control, resource, severity                         │
│  ├─ Add remediation metadata                                    │
│  └─ Generate finding IDs                                        │
└────────────────────────────┬────────────────────────────────────┘
                             ↓
┌─────────────────────────────────────────────────────────────────┐
│                    4. S3 STORAGE                                 │
├─────────────────────────────────────────────────────────────────┤
│  store_evidence()                                                │
│  ├─ raw-scans/inspec/YYYY/MM/DD/scan.json                       │
│  │  └─ Original InSpec output (7 years)                         │
│  ├─ normalized-findings/YYYY/MM/DD/findings.ndjson              │
│  │  └─ Canonical format (3 years)                               │
│  └─ snapshots/daily/YYYY/MM/snap-YYYY-MM-DD-daily.json         │
│     └─ Compliance snapshot (1 year)                             │
│                                                                   │
│  Features:                                                       │
│  ✓ Versioned (immutable history)                                │
│  ✓ Encrypted (KMS at rest)                                      │
│  ✓ Object Locked (GOVERNANCE 7 years)                           │
│  ✓ Lifecycle (Standard → IA → Glacier)                          │
└────────────────────────────┬────────────────────────────────────┘
                             ↓
┌─────────────────────────────────────────────────────────────────┐
│                  5. REPORT GENERATION                            │
├─────────────────────────────────────────────────────────────────┤
│  compliance_reporter.py                                          │
│  ├─ generate_daily_report()                                     │
│  │  └─ Compliance score, by severity, top violations            │
│  ├─ generate_audit_report(control_id)                           │
│  │  └─ Control-specific evidence, remediation history           │
│  ├─ generate_markdown_report()                                  │
│  │  └─ Human-readable format                                    │
│  └─ save_report() → reports/daily/YYYY/MM/report.md             │
└────────────────────────────┬────────────────────────────────────┘
                             ↓
┌─────────────────────────────────────────────────────────────────┐
│                     6. AUDIT ACCESS                              │
├─────────────────────────────────────────────────────────────────┤
│  Auditors với IAM role "compliance-auditor"                      │
│  ├─ Read-only access to S3 evidence bucket                      │
│  ├─ Query findings: jq, AWS CLI, Athena                         │
│  ├─ Download reports, scan results                              │
│  └─ Verify integrity: SHA-256 hashes                            │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📊 Evidence Types

### 1. Raw Scan Results

**Purpose**: Original unaltered scanner output
**Location**: `s3://evidence/raw-scans/`
**Format**: JSON
**Retention**: 7 years

**Example**: `raw-scans/inspec/2025/12/07/inspec-aws-cis-2025-12-07-10-30-00.json`

**Contents**:
- Scanner metadata (tool, version)
- All controls executed
- Pass/Fail results with evidence
- SHA-256 hash
- Timestamps

### 2. Normalized Findings

**Purpose**: Standardized queryable format
**Location**: `s3://evidence/normalized-findings/`
**Format**: NDJSON (newline-delimited JSON)
**Retention**: 3 years

**Schema**:
```json
{
  "finding_id": "find-20251207-103015-001",
  "control": {"id": "CIS-AWS-2.1.4", "title": "..."},
  "severity": "CRITICAL",
  "status": "FAIL",
  "resource": {"id": "arn:aws:s3:::my-bucket", "type": "s3_bucket"},
  "evidence": {"actual": {...}, "expected": {...}},
  "remediation": {"available": true, "method": "cloud-custodian"}
}
```

### 3. Remediation Logs

**Purpose**: Audit trail of all fixes
**Location**: `s3://evidence/remediations/`
**Format**: JSON
**Retention**: 7 years

**Contents**:
- Before/After state
- Timeline (detection → fix → verification)
- Actor (who/what triggered)
- Method (Custodian/Ansible/Manual)
- Success/Failure status

### 4. Compliance Snapshots

**Purpose**: Point-in-time compliance state
**Location**: `s3://evidence/snapshots/`
**Frequency**: Daily, Weekly, Monthly
**Retention**: 1 year

**Contents**:
- Overall compliance score
- By severity (CRITICAL/HIGH/MEDIUM/LOW)
- Top violations
- Trend vs previous period

### 5. Audit Trail

**Purpose**: Every action taken
**Location**: `s3://evidence/audit-trail/`
**Format**: NDJSON
**Retention**: 7 years

**Logged Events**:
- Scan execution
- Remediation triggered
- Exception granted
- Manual changes

---

## 🚀 Quick Start

### Demo: Complete Evidence Flow

```bash
# Run the demo script
bash evidence/scripts/demo-evidence-flow.sh
```

**Demo sẽ thực hiện**:
1. ✓ Check prerequisites (AWS CLI, Python, boto3)
2. ✓ Setup S3 evidence bucket
3. ✓ Collect evidence from sample scan
4. ✓ Store to S3 (raw, normalized, snapshot)
5. ✓ Generate compliance report
6. ✓ Display summary and next steps

### Manual Usage

#### Collect Evidence from InSpec

```bash
# 1. Run InSpec scan
inspec exec tests/inspec/aws-cis -t aws:// \
  --reporter json:scan-results.json

# 2. Collect and store evidence
python3 evidence/collectors/evidence_collector.py \
  --inspec-json scan-results.json \
  --bucket compliance-evidence-123456789012 \
  --store
```

#### Generate Daily Report

```bash
python3 evidence/reporters/compliance_reporter.py \
  --bucket compliance-evidence-123456789012 \
  --type daily \
  --date 2025-12-07 \
  --format markdown
```

#### Generate Audit Report for Control

```bash
python3 evidence/reporters/compliance_reporter.py \
  --bucket compliance-evidence-123456789012 \
  --type audit \
  --control CIS-AWS-2.1.4 \
  --format markdown \
  --save
```

---

## 🏗️ Infrastructure Setup

### Deploy Evidence Bucket with Terraform

```bash
cd evidence/terraform

# Initialize Terraform
terraform init

# Review plan
terraform plan

# Deploy
terraform apply
```

**Terraform sẽ tạo**:
- ✅ S3 bucket với versioning
- ✅ Object Lock (immutability)
- ✅ KMS encryption key
- ✅ Lifecycle policies (Standard → IA → Glacier)
- ✅ Bucket policies (deny HTTP, require MFA delete)
- ✅ IAM roles (collector, auditor)
- ✅ Access logging bucket

**Output**:
```
evidence_bucket_name = "compliance-evidence-123456789012"
kms_key_arn = "arn:aws:kms:us-east-1:123456789012:key/..."
evidence_collector_role_arn = "arn:aws:iam::123456789012:role/..."
auditor_role_arn = "arn:aws:iam::123456789012:role/..."
```

---

## 👥 For Auditors

### Accessing Evidence

**Prerequisites**:
- IAM role: `compliance-auditor`
- AWS CLI configured

**View Evidence for Date**:
```bash
# List scans for today
aws s3 ls s3://compliance-evidence-123456789012/raw-scans/inspec/$(date +%Y/%m/%d)/

# Download scan result
aws s3 cp s3://compliance-evidence-123456789012/raw-scans/inspec/2025/12/07/scan.json ./

# View compliance snapshot
aws s3 cp s3://compliance-evidence-123456789012/snapshots/daily/2025/12/snap-2025-12-07-daily.json - | jq .
```

**Query Findings**:
```bash
# Get all CRITICAL failures
aws s3 cp s3://compliance-evidence-123456789012/normalized-findings/2025/12/07/findings.ndjson - | \
  jq 'select(.severity == "CRITICAL" and .status == "FAIL")'

# Get findings for specific control
aws s3 cp s3://compliance-evidence-123456789012/normalized-findings/2025/12/07/findings.ndjson - | \
  jq 'select(.control.id == "CIS-AWS-2.1.4")'
```

**Verify Evidence Integrity**:
```bash
# Download evidence
aws s3 cp s3://evidence/raw-scans/inspec/2025/12/07/scan.json ./scan.json

# Extract embedded hash
EMBEDDED_HASH=$(jq -r '.sha256' scan.json)

# Calculate actual hash
ACTUAL_HASH=$(jq 'del(.sha256)' scan.json | shasum -a 256 | awk '{print $1}')

# Compare
if [ "$EMBEDDED_HASH" == "$ACTUAL_HASH" ]; then
  echo "✅ Evidence integrity verified"
else
  echo "❌ Evidence may be tampered"
fi
```

**Complete Audit Handbook**: [docs/AUDIT-HANDBOOK.md](docs/AUDIT-HANDBOOK.md)

---

## 📈 Compliance Metrics

### Current Status (Example)

```
Overall Compliance Score: 72%
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

By Severity:
├── CRITICAL: 100% ✅ (39/39)  ← TARGET MET
├── HIGH:      85% 🟢 (41/48)
├── MEDIUM:    65% 🟡 (44/68)
└── LOW:       40% 🟠 (10/25)

By Standard:
├── CIS AWS:   90% (54/60)
└── CIS Linux: 61% (58/95)

Top Violations:
1. CIS-LINUX-4.1.1.2 (auditd service) - 12 resources
2. CIS-AWS-4.5 (CloudWatch alarms) - 8 resources
3. CIS-LINUX-5.3.1 (PAM config) - 6 resources

Remediation Performance:
├── Total remediations: 45
├── Auto-remediated: 38 (84%)
├── Manual: 7 (16%)
└── Success rate: 98% ✅

SLA Performance:
├── CRITICAL MTTR: 2h (target: 4h) ✅
├── HIGH MTTR: 18h (target: 24h) ✅
└── MEDIUM MTTR: 4d (target: 7d) ✅
```

---

## 🔐 Security & Compliance

### Evidence Security Features

| Feature | Configuration | Purpose |
|---------|---------------|---------|
| **Versioning** | Enabled | Track all changes |
| **Object Lock** | GOVERNANCE 7 years | Immutability |
| **Encryption** | KMS (aws:kms) | Data protection at rest |
| **Access Control** | IAM roles | Least privilege |
| **Audit Logging** | S3 access logs | Track who accessed evidence |
| **Public Access** | All blocked | Prevent data leaks |
| **MFA Delete** | Required | Prevent accidental deletion |
| **Lifecycle** | Standard → IA → Glacier | Cost optimization |

### Compliance Standards Met

- ✅ **SOX**: 7-year retention
- ✅ **HIPAA**: Encryption, access logs, immutability
- ✅ **PCI-DSS**: Secure storage, audit trails
- ✅ **ISO 27001**: Evidence management
- ✅ **NIST CSF**: DE.CM (continuous monitoring)

---

## 📚 Documentation

| Document | Description | Link |
|----------|-------------|------|
| **README.md** | Quick start guide | [evidence/README.md](evidence/README.md) |
| **EVIDENCE-SCHEMA.md** | Complete schema docs | [evidence/EVIDENCE-SCHEMA.md](evidence/EVIDENCE-SCHEMA.md) |
| **AUDIT-HANDBOOK.md** | Auditor's guide | [docs/AUDIT-HANDBOOK.md](docs/AUDIT-HANDBOOK.md) |
| **evidence_collector.py** | Collector API docs | [evidence/collectors/](evidence/collectors/) |
| **compliance_reporter.py** | Reporter API docs | [evidence/reporters/](evidence/reporters/) |

---

## 🎯 Next Steps

### For Developers

1. **Integrate với CI/CD**:
   ```yaml
   # .github/workflows/compliance.yml
   - name: Collect Evidence
     run: python3 evidence/collectors/evidence_collector.py --store
   ```

2. **Schedule scans**:
   ```bash
   # Lambda/cron hourly for CRITICAL controls
   0 * * * * inspec exec tests/inspec/aws-cis --controls cis-aws-* -t aws://
   ```

3. **Setup alerts**:
   ```python
   # Lambda để alert khi có CRITICAL violations
   if finding['severity'] == 'CRITICAL' and finding['status'] == 'FAIL':
       send_slack_alert(finding)
   ```

### For Security Team

1. **Review daily snapshots**: Check compliance score trends
2. **Investigate violations**: Query findings by control ID
3. **Verify remediations**: Check auto-remediation success rate
4. **Update policies**: Add new controls as needed

### For Auditors

1. **Access evidence bucket**: Get IAM role `compliance-auditor`
2. **Review audit handbook**: [docs/AUDIT-HANDBOOK.md](docs/AUDIT-HANDBOOK.md)
3. **Generate audit reports**: Use `compliance_reporter.py`
4. **Verify integrity**: Check SHA-256 hashes

---

## 📞 Support

**Questions?**
- Slack: #cloud-security
- Email: cloud-security@company.com

**Issues?**
- GitHub: Open an issue
- On-call: security-oncall@company.com

---

**Last Updated**: 2025-12-07
**Version**: 1.0
**Status**: Production Ready ✅
**Owner**: Cloud Security Team
