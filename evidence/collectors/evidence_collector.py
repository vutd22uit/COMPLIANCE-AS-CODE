#!/usr/bin/env python3
"""
Evidence Collector for CIS Benchmark Compliance

This script collects, normalizes, and stores compliance evidence
from various scanners (InSpec, Checkov, AWS Config).
"""

import json
import hashlib
import boto3
from datetime import datetime, timezone
from typing import Dict, List, Any
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class EvidenceCollector:
    """Collects and processes compliance evidence"""

    def __init__(self, evidence_bucket: str):
        """
        Initialize evidence collector

        Args:
            evidence_bucket: S3 bucket for evidence storage
        """
        self.evidence_bucket = evidence_bucket
        self.s3_client = boto3.client('s3')

    def collect_inspec_scan(self, inspec_json_path: str) -> Dict[str, Any]:
        """
        Collect InSpec scan results and create evidence

        Args:
            inspec_json_path: Path to InSpec JSON output file

        Returns:
            Evidence dictionary
        """
        logger.info(f"Collecting InSpec scan from {inspec_json_path}")

        with open(inspec_json_path, 'r') as f:
            inspec_data = json.load(f)

        # Create evidence ID
        evidence_id = self._generate_evidence_id('inspec')

        # Calculate SHA-256
        content_hash = self._calculate_hash(json.dumps(inspec_data, sort_keys=True))

        # Create evidence structure
        evidence = {
            "evidence_type": "scan_result",
            "evidence_id": evidence_id,
            "scanner": "inspec",
            "scanner_version": inspec_data.get('version', 'unknown'),
            "profile": {
                "name": inspec_data.get('profiles', [{}])[0].get('name', 'unknown'),
                "version": inspec_data.get('profiles', [{}])[0].get('version', '1.0.0'),
                "title": inspec_data.get('profiles', [{}])[0].get('title', 'CIS Benchmark')
            },
            "scan_metadata": {
                "start_time": inspec_data.get('statistics', {}).get('start_time', datetime.now(timezone.utc).isoformat()),
                "duration_seconds": inspec_data.get('statistics', {}).get('duration', 0)
            },
            "statistics": {
                "total_controls": len(inspec_data.get('profiles', [{}])[0].get('controls', [])),
                "passed": sum(1 for c in inspec_data.get('profiles', [{}])[0].get('controls', [])
                             if c.get('results', [{}])[0].get('status') == 'passed'),
                "failed": sum(1 for c in inspec_data.get('profiles', [{}])[0].get('controls', [])
                             if c.get('results', [{}])[0].get('status') == 'failed'),
                "skipped": sum(1 for c in inspec_data.get('profiles', [{}])[0].get('controls', [])
                              if c.get('results', [{}])[0].get('status') == 'skipped')
            },
            "controls": inspec_data.get('profiles', [{}])[0].get('controls', []),
            "sha256": content_hash,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        logger.info(f"InSpec evidence collected: {evidence_id}")
        logger.info(f"  Controls: {evidence['statistics']['total_controls']}")
        logger.info(f"  Passed: {evidence['statistics']['passed']}")
        logger.info(f"  Failed: {evidence['statistics']['failed']}")

        return evidence

    def normalize_findings(self, raw_evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Normalize raw scan results to canonical finding format

        Args:
            raw_evidence: Raw evidence dictionary

        Returns:
            List of normalized findings
        """
        logger.info(f"Normalizing findings from {raw_evidence['evidence_id']}")

        normalized_findings = []

        scanner = raw_evidence['scanner']

        if scanner == 'inspec':
            normalized_findings = self._normalize_inspec(raw_evidence)
        elif scanner == 'checkov':
            normalized_findings = self._normalize_checkov(raw_evidence)
        else:
            logger.warning(f"Unknown scanner type: {scanner}")

        logger.info(f"Normalized {len(normalized_findings)} findings")
        return normalized_findings

    def _normalize_inspec(self, evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Normalize InSpec evidence to canonical format"""

        findings = []

        for control in evidence.get('controls', []):
            for result in control.get('results', []):
                if result.get('status') in ['failed', 'passed']:
                    finding = {
                        "finding_id": self._generate_finding_id(),
                        "evidence_id": evidence['evidence_id'],
                        "timestamp": datetime.now(timezone.utc).isoformat(),

                        "control": {
                            "id": control.get('tags', {}).get('cis', control.get('id')),
                            "title": control.get('title', ''),
                            "standard": control.get('tags', {}).get('standard', 'CIS Benchmark'),
                            "section": control.get('tags', {}).get('section', ''),
                            "description": control.get('desc', '')
                        },

                        "severity": control.get('tags', {}).get('severity', 'MEDIUM').upper(),
                        "status": "FAIL" if result.get('status') == 'failed' else "PASS",

                        "resource": {
                            "id": result.get('resource', 'unknown'),
                            "type": self._infer_resource_type(result.get('resource', '')),
                            "name": self._extract_resource_name(result.get('resource', '')),
                        },

                        "evidence": {
                            "scanner": "inspec",
                            "message": result.get('message', ''),
                            "code_desc": result.get('code_desc', '')
                        },

                        "remediation": {
                            "available": self._is_auto_remediable(control.get('tags', {}).get('cis', '')),
                            "method": self._get_remediation_method(control.get('tags', {}).get('cis', '')),
                            "status": "pending"
                        },

                        "metadata": {
                            "first_seen": datetime.now(timezone.utc).isoformat(),
                            "false_positive": False,
                            "exception_id": None
                        }
                    }

                    findings.append(finding)

        return findings

    def _normalize_checkov(self, evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Normalize Checkov evidence to canonical format"""
        # Simplified Checkov normalization
        findings = []
        # Implementation details...
        return findings

    def store_evidence(self, evidence: Dict[str, Any], evidence_type: str):
        """
        Store evidence to S3 bucket

        Args:
            evidence: Evidence dictionary
            evidence_type: Type of evidence (raw-scans, normalized-findings, etc.)
        """
        timestamp = datetime.now(timezone.utc)
        year = timestamp.strftime('%Y')
        month = timestamp.strftime('%m')
        day = timestamp.strftime('%d')

        scanner = evidence.get('scanner', 'unknown')
        evidence_id = evidence.get('evidence_id', 'unknown')

        # Build S3 key
        if evidence_type == 'raw-scans':
            s3_key = f"{evidence_type}/{scanner}/{year}/{month}/{day}/{evidence_id}.json"
        elif evidence_type == 'normalized-findings':
            s3_key = f"{evidence_type}/{year}/{month}/{day}/{evidence_id}.ndjson"
        else:
            s3_key = f"{evidence_type}/{year}/{month}/{day}/{evidence_id}.json"

        logger.info(f"Storing evidence to s3://{self.evidence_bucket}/{s3_key}")

        # Convert to JSON
        evidence_json = json.dumps(evidence, indent=2, sort_keys=True)

        # Upload to S3
        try:
            self.s3_client.put_object(
                Bucket=self.evidence_bucket,
                Key=s3_key,
                Body=evidence_json.encode('utf-8'),
                ContentType='application/json',
                ServerSideEncryption='aws:kms',
                Metadata={
                    'evidence-id': evidence.get('evidence_id', ''),
                    'evidence-type': evidence_type,
                    'scanner': scanner,
                    'timestamp': timestamp.isoformat()
                }
            )
            logger.info(f"Evidence stored successfully: {s3_key}")
            return s3_key

        except Exception as e:
            logger.error(f"Failed to store evidence: {e}")
            raise

    def store_normalized_findings(self, findings: List[Dict[str, Any]]):
        """
        Store normalized findings as NDJSON

        Args:
            findings: List of normalized finding dictionaries
        """
        if not findings:
            logger.warning("No findings to store")
            return

        timestamp = datetime.now(timezone.utc)
        year = timestamp.strftime('%Y')
        month = timestamp.strftime('%m')
        day = timestamp.strftime('%d')
        hour = timestamp.strftime('%H')
        minute = timestamp.strftime('%M')

        # Build S3 key
        s3_key = f"normalized-findings/{year}/{month}/{day}/findings-{year}-{month}-{day}-{hour}-{minute}.ndjson"

        logger.info(f"Storing {len(findings)} normalized findings to s3://{self.evidence_bucket}/{s3_key}")

        # Convert to NDJSON (newline-delimited JSON)
        ndjson_lines = [json.dumps(finding, sort_keys=True) for finding in findings]
        ndjson_content = '\n'.join(ndjson_lines)

        # Upload to S3
        try:
            self.s3_client.put_object(
                Bucket=self.evidence_bucket,
                Key=s3_key,
                Body=ndjson_content.encode('utf-8'),
                ContentType='application/x-ndjson',
                ServerSideEncryption='aws:kms',
                Metadata={
                    'finding-count': str(len(findings)),
                    'timestamp': timestamp.isoformat()
                }
            )
            logger.info(f"Normalized findings stored successfully: {s3_key}")
            return s3_key

        except Exception as e:
            logger.error(f"Failed to store findings: {e}")
            raise

    def create_compliance_snapshot(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Create compliance snapshot from current findings

        Args:
            findings: List of current findings

        Returns:
            Compliance snapshot dictionary
        """
        logger.info(f"Creating compliance snapshot from {len(findings)} findings")

        total_controls = len(set(f['control']['id'] for f in findings))
        passed = sum(1 for f in findings if f['status'] == 'PASS')
        failed = sum(1 for f in findings if f['status'] == 'FAIL')

        snapshot = {
            "snapshot_id": self._generate_snapshot_id(),
            "snapshot_type": "daily",
            "timestamp": datetime.now(timezone.utc).isoformat(),

            "overall": {
                "compliance_score": round((passed / len(findings) * 100), 2) if findings else 0,
                "total_controls": total_controls,
                "controls_passed": passed,
                "controls_failed": failed
            },

            "by_severity": self._calculate_by_severity(findings),
            "top_violations": self._get_top_violations(findings, limit=10)
        }

        logger.info(f"Snapshot created: {snapshot['snapshot_id']}")
        logger.info(f"  Compliance Score: {snapshot['overall']['compliance_score']}%")

        return snapshot

    def _calculate_by_severity(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate compliance by severity level"""

        severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        by_severity = {}

        for severity in severities:
            severity_findings = [f for f in findings if f['severity'] == severity]
            total = len(severity_findings)
            passed = sum(1 for f in severity_findings if f['status'] == 'PASS')

            by_severity[severity] = {
                "total": total,
                "passed": passed,
                "failed": total - passed,
                "compliance_percentage": round((passed / total * 100), 2) if total > 0 else 0
            }

        return by_severity

    def _get_top_violations(self, findings: List[Dict[str, Any]], limit: int = 10) -> List[Dict[str, Any]]:
        """Get top violations by occurrence count"""

        # Group by control ID
        violations = {}
        for f in findings:
            if f['status'] == 'FAIL':
                control_id = f['control']['id']
                if control_id not in violations:
                    violations[control_id] = {
                        "control_id": control_id,
                        "title": f['control']['title'],
                        "severity": f['severity'],
                        "affected_resources": 0
                    }
                violations[control_id]['affected_resources'] += 1

        # Sort by affected resources
        top_violations = sorted(violations.values(), key=lambda x: x['affected_resources'], reverse=True)

        return top_violations[:limit]

    @staticmethod
    def _generate_evidence_id(scanner: str) -> str:
        """Generate unique evidence ID"""
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
        import uuid
        unique_id = str(uuid.uuid4())[:8]
        return f"scan-{timestamp}-{scanner}-{unique_id}"

    @staticmethod
    def _generate_finding_id() -> str:
        """Generate unique finding ID"""
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
        import uuid
        unique_id = str(uuid.uuid4())[:8]
        return f"find-{timestamp}-{unique_id}"

    @staticmethod
    def _generate_snapshot_id() -> str:
        """Generate snapshot ID"""
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d')
        return f"snap-{timestamp}-daily"

    @staticmethod
    def _calculate_hash(content: str) -> str:
        """Calculate SHA-256 hash of content"""
        return hashlib.sha256(content.encode('utf-8')).hexdigest()

    @staticmethod
    def _infer_resource_type(resource_arn: str) -> str:
        """Infer resource type from ARN or resource name"""
        if ':s3:::' in resource_arn:
            return 's3_bucket'
        elif ':ec2:' in resource_arn:
            return 'ec2_instance'
        elif ':rds:' in resource_arn:
            return 'rds_database'
        elif ':iam:' in resource_arn:
            return 'iam_user'
        else:
            return 'unknown'

    @staticmethod
    def _extract_resource_name(resource_id: str) -> str:
        """Extract resource name from ARN or ID"""
        if ':::' in resource_id:
            return resource_id.split(':::')[-1]
        elif '/' in resource_id:
            return resource_id.split('/')[-1]
        else:
            return resource_id

    @staticmethod
    def _is_auto_remediable(control_id: str) -> bool:
        """Check if control has auto-remediation available"""
        auto_remediable_controls = [
            'CIS-AWS-2.1.4',  # S3 public access block
            'CIS-AWS-2.1.2',  # S3 encryption
            'CIS-AWS-2.2.1',  # EBS encryption
            'CIS-AWS-3.1',    # CloudTrail enabled
        ]
        return control_id in auto_remediable_controls

    @staticmethod
    def _get_remediation_method(control_id: str) -> str:
        """Get remediation method for control"""
        if control_id.startswith('CIS-AWS-2.1'):
            return 'cloud-custodian'
        elif control_id.startswith('CIS-LINUX'):
            return 'ansible'
        else:
            return 'manual'


def main():
    """Main function for testing"""

    import argparse

    parser = argparse.ArgumentParser(description='Collect compliance evidence')
    parser.add_argument('--inspec-json', help='Path to InSpec JSON output')
    parser.add_argument('--bucket', required=True, help='S3 evidence bucket name')
    parser.add_argument('--store', action='store_true', help='Store evidence to S3')

    args = parser.parse_args()

    # Initialize collector
    collector = EvidenceCollector(evidence_bucket=args.bucket)

    # Collect InSpec scan
    if args.inspec_json:
        evidence = collector.collect_inspec_scan(args.inspec_json)

        # Normalize findings
        findings = collector.normalize_findings(evidence)

        # Store evidence
        if args.store:
            collector.store_evidence(evidence, 'raw-scans')
            collector.store_normalized_findings(findings)

            # Create snapshot
            snapshot = collector.create_compliance_snapshot(findings)
            collector.store_evidence(snapshot, 'snapshots/daily')

        # Print summary
        print(f"\n{'='*60}")
        print(f"Evidence Collection Summary")
        print(f"{'='*60}")
        print(f"Evidence ID: {evidence['evidence_id']}")
        print(f"Total Controls: {evidence['statistics']['total_controls']}")
        print(f"Passed: {evidence['statistics']['passed']}")
        print(f"Failed: {evidence['statistics']['failed']}")
        print(f"Normalized Findings: {len(findings)}")
        print(f"{'='*60}\n")


if __name__ == '__main__':
    main()
