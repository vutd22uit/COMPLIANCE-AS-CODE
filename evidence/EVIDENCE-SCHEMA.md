# Evidence Collection Schema

## Overview

This document defines the canonical evidence schema for CIS Benchmark compliance auditing.

All evidence is stored in **immutable, versioned S3 buckets** with **7-year retention** for audit compliance.

---

## Evidence Types

### 1. Scan Results (Raw)

**Purpose**: Original scanner output for audit trail
**Format**: JSON
**Retention**: 7 years
**Storage**: `s3://evidence/raw-scans/`

#### InSpec Scan Result

```json
{
  "evidence_type": "scan_result",
  "evidence_id": "scan-20251207-103000-abc123",
  "scanner": "inspec",
  "scanner_version": "5.22.3",
  "profile": {
    "name": "aws-cis-benchmark",
    "version": "1.5.0",
    "title": "CIS AWS Foundations Benchmark"
  },
  "scan_metadata": {
    "start_time": "2025-12-07T10:30:00Z",
    "end_time": "2025-12-07T10:32:15Z",
    "duration_seconds": 135,
    "target": "aws://123456789012",
    "region": "us-east-1"
  },
  "platform": {
    "name": "aws",
    "release": "aws-sdk-2.0"
  },
  "statistics": {
    "total_controls": 60,
    "passed": 42,
    "failed": 15,
    "skipped": 3,
    "error": 0
  },
  "controls": [
    {
      "id": "cis-aws-2.1.4",
      "title": "Ensure S3 buckets are configured with 'Block public access'",
      "desc": "Amazon S3 Block Public Access provides settings...",
      "impact": 1.0,
      "tags": {
        "cis": "CIS-AWS-2.1.4",
        "severity": "critical",
        "standard": "CIS AWS Foundations Benchmark v1.5.0",
        "section": "2.1 Storage"
      },
      "results": [
        {
          "status": "failed",
          "code_desc": "S3 Bucket my-test-bucket should have block public access enabled",
          "run_time": 0.425,
          "start_time": "2025-12-07T10:30:15Z",
          "resource": "arn:aws:s3:::my-test-bucket",
          "message": "expected block_public_acls to be true, got false"
        }
      ]
    }
  ],
  "sha256": "a3c5f8d9e2b1...",
  "signature": "digital_signature_here"
}
```

#### Checkov Scan Result

```json
{
  "evidence_type": "scan_result",
  "evidence_id": "scan-20251207-090000-def456",
  "scanner": "checkov",
  "scanner_version": "3.1.0",
  "scan_metadata": {
    "start_time": "2025-12-07T09:00:00Z",
    "end_time": "2025-12-07T09:00:45Z",
    "duration_seconds": 45,
    "framework": "terraform",
    "repository": "https://github.com/org/repo",
    "branch": "main",
    "commit_sha": "abc123def456"
  },
  "summary": {
    "passed": 28,
    "failed": 5,
    "skipped": 2,
    "parsing_errors": 0
  },
  "results": {
    "passed_checks": [...],
    "failed_checks": [
      {
        "check_id": "CKV_AWS_21",
        "check_name": "Ensure S3 bucket has block public access enabled",
        "check_result": {
          "result": "FAILED",
          "evaluated_keys": ["public_access_block"]
        },
        "file_path": "/terraform/s3.tf",
        "file_line_range": [15, 25],
        "resource": "aws_s3_bucket.example",
        "severity": "CRITICAL",
        "guideline": "https://docs.bridgecrew.io/docs/s3_14"
      }
    ]
  },
  "sha256": "b4d6f9e3c2a1...",
  "signature": "digital_signature_here"
}
```

---

### 2. Normalized Findings

**Purpose**: Canonical format for all findings across scanners
**Format**: NDJSON (newline-delimited JSON)
**Retention**: 3 years
**Storage**: `s3://evidence/normalized-findings/`

```json
{
  "finding_id": "find-20251207-103015-001",
  "evidence_id": "scan-20251207-103000-abc123",
  "timestamp": "2025-12-07T10:30:15Z",

  "control": {
    "id": "CIS-AWS-2.1.4",
    "title": "Ensure S3 buckets are configured with 'Block public access'",
    "standard": "CIS AWS Foundations Benchmark v1.5.0",
    "section": "2.1 Storage",
    "description": "Amazon S3 Block Public Access provides settings to manage public access to S3 resources."
  },

  "severity": "CRITICAL",
  "status": "FAIL",

  "resource": {
    "id": "arn:aws:s3:::my-test-bucket",
    "type": "s3_bucket",
    "name": "my-test-bucket",
    "account_id": "123456789012",
    "region": "us-east-1",
    "tags": {
      "Environment": "production",
      "Owner": "platform-team"
    }
  },

  "evidence": {
    "scanner": "inspec",
    "actual_value": {
      "block_public_acls": false,
      "block_public_policy": false,
      "ignore_public_acls": false,
      "restrict_public_buckets": false
    },
    "expected_value": {
      "block_public_acls": true,
      "block_public_policy": true,
      "ignore_public_acls": true,
      "restrict_public_buckets": true
    },
    "delta": ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]
  },

  "remediation": {
    "available": true,
    "method": "cloud-custodian",
    "policy": "s3-enforce-block-public-access",
    "status": "pending",
    "sla_hours": 4
  },

  "risk": {
    "impact": "Public data exposure",
    "likelihood": "High",
    "cvss_score": 9.1
  },

  "metadata": {
    "first_seen": "2025-12-07T10:30:15Z",
    "last_seen": "2025-12-07T10:30:15Z",
    "occurrence_count": 1,
    "false_positive": false,
    "exception_id": null
  }
}
```

---

### 3. Remediation Logs

**Purpose**: Audit trail of all remediation actions
**Format**: JSON
**Retention**: 7 years
**Storage**: `s3://evidence/remediations/`

```json
{
  "remediation_id": "rem-20251207-103500-xyz789",
  "finding_id": "find-20251207-103015-001",
  "control_id": "CIS-AWS-2.1.4",

  "resource": {
    "id": "arn:aws:s3:::my-test-bucket",
    "type": "s3_bucket",
    "account_id": "123456789012",
    "region": "us-east-1"
  },

  "timeline": {
    "violation_detected": "2025-12-07T10:30:15Z",
    "remediation_triggered": "2025-12-07T10:35:00Z",
    "remediation_started": "2025-12-07T10:35:02Z",
    "remediation_completed": "2025-12-07T10:35:08Z",
    "verification_completed": "2025-12-07T10:36:00Z",
    "total_duration_seconds": 60
  },

  "remediation": {
    "method": "cloud-custodian",
    "policy_name": "s3-enforce-block-public-access",
    "action_type": "set-public-access-block",
    "triggered_by": "auto",
    "approved_by": null,
    "approval_required": false
  },

  "state_change": {
    "before": {
      "block_public_acls": false,
      "block_public_policy": false,
      "ignore_public_acls": false,
      "restrict_public_buckets": false
    },
    "after": {
      "block_public_acls": true,
      "block_public_policy": true,
      "ignore_public_acls": true,
      "restrict_public_buckets": true
    },
    "diff": {
      "changed_fields": ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"],
      "patch": [
        {"op": "replace", "path": "/block_public_acls", "value": true},
        {"op": "replace", "path": "/block_public_policy", "value": true},
        {"op": "replace", "path": "/ignore_public_acls", "value": true},
        {"op": "replace", "path": "/restrict_public_buckets", "value": true}
      ]
    }
  },

  "verification": {
    "method": "inspec",
    "result": "PASS",
    "verified_at": "2025-12-07T10:36:00Z",
    "evidence_id": "scan-20251207-103600-verify123"
  },

  "outcome": {
    "success": true,
    "error": null,
    "rollback_required": false
  },

  "notifications": [
    {
      "channel": "slack",
      "sent_at": "2025-12-07T10:35:10Z",
      "message": "S3 bucket my-test-bucket: Public access blocked automatically (CIS-AWS-2.1.4)"
    }
  ],

  "metadata": {
    "cost_saved": 0.0,
    "business_impact": "Low",
    "change_ticket": null
  },

  "sha256": "c5e7g1h3d4b2...",
  "signature": "digital_signature_here"
}
```

---

### 4. Compliance Snapshots

**Purpose**: Point-in-time compliance state
**Format**: JSON
**Retention**: 1 year
**Storage**: `s3://evidence/snapshots/`

#### Daily Snapshot

```json
{
  "snapshot_id": "snap-20251207-daily",
  "snapshot_type": "daily",
  "timestamp": "2025-12-07T00:00:00Z",

  "overall": {
    "compliance_score": 72.5,
    "total_controls": 155,
    "controls_passed": 112,
    "controls_failed": 40,
    "controls_skipped": 3,
    "controls_error": 0
  },

  "by_standard": {
    "CIS-AWS": {
      "total_controls": 60,
      "passed": 54,
      "failed": 6,
      "compliance_percentage": 90.0
    },
    "CIS-Linux": {
      "total_controls": 95,
      "passed": 58,
      "failed": 34,
      "compliance_percentage": 61.1
    }
  },

  "by_severity": {
    "CRITICAL": {
      "total": 39,
      "passed": 39,
      "failed": 0,
      "compliance_percentage": 100.0
    },
    "HIGH": {
      "total": 48,
      "passed": 41,
      "failed": 7,
      "compliance_percentage": 85.4
    },
    "MEDIUM": {
      "total": 68,
      "passed": 44,
      "failed": 24,
      "compliance_percentage": 64.7
    },
    "LOW": {
      "total": 25,
      "passed": 10,
      "failed": 15,
      "compliance_percentage": 40.0
    }
  },

  "by_section": {
    "CIS-AWS-1-IAM": {
      "controls": 21,
      "passed": 18,
      "compliance_percentage": 85.7
    },
    "CIS-AWS-2-Storage": {
      "controls": 11,
      "passed": 11,
      "compliance_percentage": 100.0
    }
  },

  "top_violations": [
    {
      "control_id": "CIS-LINUX-4.1.1.2",
      "title": "Ensure auditd service is enabled",
      "severity": "HIGH",
      "affected_resources": 12
    },
    {
      "control_id": "CIS-AWS-4.5",
      "title": "Ensure a log metric filter and alarm exist for CloudTrail config changes",
      "severity": "HIGH",
      "affected_resources": 1
    }
  ],

  "trend": {
    "previous_snapshot": "snap-20251206-daily",
    "score_change": +2.5,
    "new_violations": 3,
    "fixed_violations": 8,
    "net_improvement": 5
  },

  "remediation_metrics": {
    "total_remediations": 8,
    "auto_remediated": 6,
    "manual_remediated": 2,
    "pending_remediation": 5,
    "avg_remediation_time_hours": 3.2
  }
}
```

---

### 5. Audit Trail

**Purpose**: Who did what when
**Format**: JSON
**Retention**: 7 years
**Storage**: `s3://evidence/audit-trail/`

```json
{
  "event_id": "evt-20251207-103500-audit001",
  "timestamp": "2025-12-07T10:35:00Z",

  "event_type": "remediation.executed",
  "event_category": "compliance",

  "actor": {
    "type": "system",
    "id": "cloud-custodian-lambda",
    "arn": "arn:aws:lambda:us-east-1:123456789012:function:custodian-remediation",
    "ip_address": "10.0.1.50",
    "user_agent": "cloud-custodian/0.9.30"
  },

  "resource": {
    "type": "s3_bucket",
    "id": "arn:aws:s3:::my-test-bucket",
    "account_id": "123456789012",
    "region": "us-east-1"
  },

  "action": {
    "operation": "s3:PutPublicAccessBlock",
    "parameters": {
      "BlockPublicAcls": true,
      "BlockPublicPolicy": true,
      "IgnorePublicAcls": true,
      "RestrictPublicBuckets": true
    },
    "result": "success"
  },

  "compliance_context": {
    "control_id": "CIS-AWS-2.1.4",
    "finding_id": "find-20251207-103015-001",
    "remediation_id": "rem-20251207-103500-xyz789",
    "severity": "CRITICAL"
  },

  "source": {
    "system": "compliance-engine",
    "request_id": "req-abc123def456"
  }
}
```

---

## Storage Structure

```
s3://compliance-evidence-123456789012/
├── raw-scans/
│   ├── inspec/
│   │   ├── 2025/
│   │   │   ├── 12/
│   │   │   │   ├── 07/
│   │   │   │   │   ├── inspec-aws-cis-2025-12-07-10-30-00.json
│   │   │   │   │   ├── inspec-linux-cis-2025-12-07-11-00-00.json
│   │   │   │   │   └── ...
│   │   │   │   └── ...
│   │   │   └── ...
│   │   └── ...
│   ├── checkov/
│   │   └── 2025/12/07/...
│   └── scoutsuite/
│       └── 2025/12/07/...
│
├── normalized-findings/
│   └── 2025/
│       └── 12/
│           └── 07/
│               ├── findings-2025-12-07-10-30.ndjson
│               └── ...
│
├── remediations/
│   └── 2025/
│       └── 12/
│           └── 07/
│               ├── rem-20251207-103500-xyz789.json
│               └── ...
│
├── snapshots/
│   ├── daily/
│   │   ├── 2025/
│   │   │   └── 12/
│   │   │       └── snap-20251207-daily.json
│   ├── weekly/
│   │   └── 2025/
│   │       └── 12/
│   │           └── snap-20251208-weekly.json
│   └── monthly/
│       └── 2025/
│           └── snap-20251201-monthly.json
│
├── audit-trail/
│   └── 2025/
│       └── 12/
│           └── 07/
│               ├── audit-2025-12-07-10.ndjson
│               └── ...
│
└── reports/
    ├── daily/
    │   └── compliance-report-2025-12-07.pdf
    ├── weekly/
    │   └── compliance-report-2025-week-49.pdf
    └── monthly/
        └── compliance-report-2025-12.pdf
```

---

## S3 Bucket Configuration

### Versioning
```json
{
  "Status": "Enabled"
}
```

### Object Lock (Immutability)
```json
{
  "ObjectLockEnabled": "Enabled",
  "Rule": {
    "DefaultRetention": {
      "Mode": "GOVERNANCE",
      "Days": 2555
    }
  }
}
```

### Lifecycle Policy
```json
{
  "Rules": [
    {
      "Id": "raw-scans-archive",
      "Status": "Enabled",
      "Filter": {"Prefix": "raw-scans/"},
      "Transitions": [
        {"Days": 90, "StorageClass": "STANDARD_IA"},
        {"Days": 365, "StorageClass": "GLACIER"}
      ],
      "Expiration": {"Days": 2555}
    },
    {
      "Id": "normalized-findings-archive",
      "Status": "Enabled",
      "Filter": {"Prefix": "normalized-findings/"},
      "Transitions": [
        {"Days": 180, "StorageClass": "STANDARD_IA"},
        {"Days": 730, "StorageClass": "GLACIER"}
      ],
      "Expiration": {"Days": 1095}
    }
  ]
}
```

### Encryption
```json
{
  "SSEAlgorithm": "aws:kms",
  "KMSMasterKeyID": "arn:aws:kms:us-east-1:123456789012:key/compliance-evidence-key"
}
```

---

## Evidence Integrity

### SHA-256 Hash
Every evidence file includes a SHA-256 hash of its content for integrity verification.

### Digital Signature
Critical evidence (remediations, audit trail) includes digital signatures.

### Chain of Custody
```json
{
  "chain_of_custody": [
    {
      "timestamp": "2025-12-07T10:30:15Z",
      "actor": "inspec-scanner",
      "action": "evidence_created",
      "hash": "a3c5f8d9e2b1..."
    },
    {
      "timestamp": "2025-12-07T10:30:20Z",
      "actor": "normalizer-lambda",
      "action": "evidence_processed",
      "hash": "b4d6f9e3c2a1..."
    },
    {
      "timestamp": "2025-12-07T10:30:25Z",
      "actor": "s3-upload",
      "action": "evidence_stored",
      "hash": "c5e7g1h3d4b2..."
    }
  ]
}
```

---

## Query Examples

### Get all CRITICAL failures for a date
```bash
aws s3 cp s3://evidence/normalized-findings/2025/12/07/findings.ndjson - | \
  jq -r 'select(.severity == "CRITICAL" and .status == "FAIL")'
```

### Get remediation history for a resource
```bash
aws s3 ls s3://evidence/remediations/2025/12/ --recursive | \
  xargs -I {} aws s3 cp s3://{} - | \
  jq -r 'select(.resource.id == "arn:aws:s3:::my-bucket")'
```

### Calculate compliance score from snapshot
```bash
aws s3 cp s3://evidence/snapshots/daily/2025/12/07/snap-20251207-daily.json - | \
  jq '.overall.compliance_score'
```

---

**Last Updated**: 2025-12-07
**Version**: 1.0
