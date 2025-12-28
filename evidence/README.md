# Evidence Collection System - OpenStack CIS Benchmark

## Overview

This directory contains the **Evidence Collection System** for OpenStack CIS Benchmark compliance auditing.

All compliance evidence is **immutable**, **versioned**, **encrypted**, and **retained for 7 years**.

---

## Directory Structure

```
evidence/
├── README.md                    # This file
├── EVIDENCE-SCHEMA.md          # Complete evidence schema documentation
│
├── collectors/                  # Evidence collection scripts
│   ├── evidence_collector.py   # Main collector (InSpec, OpenSCAP → Storage)
│   └── __init__.py
│
├── reporters/                   # Report generation
│   ├── compliance_reporter.py  # Generate daily/audit reports
│   └── __init__.py
│
├── samples/                     # Sample evidence data for testing
│   ├── sample-inspec-scan.json  # Example InSpec output
│   └── sample-remediation.json  # Example remediation log
│
└── scripts/                     # Utility scripts
    ├── demo-evidence-flow.sh    # Demo the complete flow
    ├── verify-integrity.sh      # Verify evidence integrity
    └── generate-sample-data.py  # Generate test data
```

---

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Run InSpec Scan & Collect Evidence

```bash
# Run InSpec scan on OpenStack controller
inspec exec tests/inspec/openstack-cis \
  -t ssh://root@controller-node \
  --reporter json:scan-results.json \
  --chef-license accept-silent

# Collect and store evidence
python evidence/collectors/evidence_collector.py \
  --inspec-json scan-results.json \
  --evidence-path ./evidence_store \
  --store
```

### 3. Generate Compliance Report

```bash
# Daily report
python evidence/reporters/compliance_reporter.py \
  --evidence-path ./evidence_store \
  --type daily \
  --date 2025-12-29 \
  --format markdown
```

---

## Evidence Types

### 1. Raw Scan Results
- **Purpose**: Original scanner output
- **Format**: JSON
- **Location**: `evidence_store/raw-scans/{scanner}/{year}/{month}/{day}/`
- **Retention**: 7 years

### 2. Normalized Findings
- **Purpose**: Canonical format across all scanners
- **Format**: NDJSON (newline-delimited JSON)
- **Location**: `evidence_store/normalized-findings/{year}/{month}/{day}/`
- **Retention**: 3 years

### 3. Remediation Logs
- **Purpose**: Audit trail of all fixes
- **Format**: JSON
- **Location**: `evidence_store/remediations/{year}/{month}/{day}/`
- **Retention**: 7 years

### 4. Compliance Snapshots
- **Purpose**: Point-in-time compliance state
- **Format**: JSON
- **Location**: `evidence_store/snapshots/daily/{year}/{month}/`
- **Retention**: 1 year

---

## Python API Usage

### Collecting Evidence

```python
from evidence.collectors.evidence_collector import EvidenceCollector

# Initialize collector
collector = EvidenceCollector(evidence_path="./evidence_store")

# Collect InSpec scan
evidence = collector.collect_inspec_scan("scan-results.json")

# Normalize findings
findings = collector.normalize_findings(evidence)

# Store evidence
collector.store_evidence(evidence, 'raw-scans')
collector.store_normalized_findings(findings)

# Create compliance snapshot
snapshot = collector.create_compliance_snapshot(findings)
collector.store_evidence(snapshot, 'snapshots/daily')
```

### Generating Reports

```python
from evidence.reporters.compliance_reporter import ComplianceReporter

# Initialize reporter
reporter = ComplianceReporter(evidence_path="./evidence_store")

# Generate daily report
daily_report = reporter.generate_daily_report(date="2025-12-29")

# Generate markdown report
markdown = reporter.generate_markdown_report(daily_report)
print(markdown)

# Save report
reporter.save_report(daily_report, format='markdown')
```

---

## Evidence Schema

### Canonical Finding Format (OpenStack)

```json
{
  "finding_id": "find-20251229-103015-abc12345",
  "timestamp": "2025-12-29T10:30:15Z",

  "control": {
    "id": "os-identity-1.1",
    "title": "Ensure keystone.conf ownership is set to root:keystone",
    "standard": "CIS OpenStack Foundations Benchmark",
    "section": "1. Identity (Keystone)"
  },

  "severity": "CRITICAL",
  "status": "FAIL",

  "resource": {
    "type": "keystone",
    "id": "/etc/keystone/keystone.conf",
    "config_file": "/etc/keystone/keystone.conf",
    "hostname": "controller-node"
  },

  "evidence": {
    "scanner": "inspec",
    "message": "File owner is 'nova' instead of 'root'",
    "actual_value": {"owner": "nova"},
    "expected_value": {"owner": "root"}
  },

  "remediation": {
    "available": true,
    "method": "ansible",
    "playbook": "remediation/ansible/cis-openstack-remediation.yml",
    "status": "pending"
  }
}
```

---

## OpenStack Service Mapping

| Control Prefix | Service | Config File |
|---------------|---------|-------------|
| `os-identity-*` | Keystone | `/etc/keystone/keystone.conf` |
| `os-compute-*` | Nova | `/etc/nova/nova.conf` |
| `os-networking-*` | Neutron | `/etc/neutron/neutron.conf` |
| `os-storage-*` | Cinder | `/etc/cinder/cinder.conf` |
| `os-image-*` | Glance | `/etc/glance/glance-api.conf` |
| `os-dashboard-*` | Horizon | `/etc/openstack-dashboard/local_settings.py` |
| `os-orchestration-*` | Heat | `/etc/heat/heat.conf` |
| `cis-*` | Linux OS | Various system files |

---

## Compliance Metrics

### Key Performance Indicators (KPIs)

| Metric | Target | Description |
|--------|--------|-------------|
| **Overall Compliance** | ≥ 80% | All controls passing |
| **CRITICAL Compliance** | 100% | Must be fully compliant |
| **HIGH Compliance** | ≥ 95% | Priority focus |
| **Mean Time to Detect (MTTD)** | < 1 hour | Scan frequency |
| **Mean Time to Remediate (MTTR)** | < 4 hours | For CRITICAL issues |

### Compliance Score Calculation

```python
# Simple score
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

---

## Integration with CI/CD

### GitHub Actions

```yaml
- name: Run OpenStack Compliance Scan
  run: |
    # Run InSpec
    inspec exec tests/inspec/openstack-cis \
      -t ssh://root@${{ secrets.CONTROLLER_HOST }} \
      --reporter json:scan.json \
      --chef-license accept-silent

    # Collect evidence
    python evidence/collectors/evidence_collector.py \
      --inspec-json scan.json \
      --evidence-path ./evidence_store \
      --store

    # Generate report
    python evidence/reporters/compliance_reporter.py \
      --evidence-path ./evidence_store \
      --type daily \
      --format markdown \
      --save
```

---

## For Auditors

Key points:
- All evidence is **timestamped** with ISO 8601 format
- All evidence includes **SHA-256 hash** for integrity
- Evidence includes **before/after states** for remediations
- Scan frequency: **Daily** (configurable to hourly for CRITICAL)
- Retention: **7 years** for compliance

### Accessing Evidence

```bash
# View evidence for a specific date
ls evidence_store/raw-scans/inspec/2025/12/29/

# View normalized findings
cat evidence_store/normalized-findings/2025/12/29/findings-*.ndjson | jq .

# Query findings for a control
cat evidence_store/normalized-findings/2025/12/29/*.ndjson | \
  jq -r 'select(.control.id == "os-identity-1.1")'

# View compliance snapshot
cat evidence_store/snapshots/daily/2025/12/snap-20251229-daily.json | jq .
```

---

## References

- [Evidence Schema Documentation](EVIDENCE-SCHEMA.md)
- [CIS OpenStack Benchmark](https://www.cisecurity.org/benchmark/openstack)
- [InSpec Documentation](https://docs.chef.io/inspec/)
- [OpenStack Security Guide](https://docs.openstack.org/security-guide/)

---

**Last Updated**: 2025-12-29
**Version**: 2.0 (OpenStack)
**Owner**: Cloud Security Team
