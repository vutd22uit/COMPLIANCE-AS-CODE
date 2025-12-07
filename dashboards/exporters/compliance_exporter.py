#!/usr/bin/env python3
"""
Prometheus Exporter for Compliance Metrics
Exposes CIS compliance scan results as Prometheus metrics
"""

import json
import time
import glob
import os
from datetime import datetime
from prometheus_client import start_http_server, Gauge, Counter, Info
from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily, REGISTRY


class ComplianceCollector:
    """Collects compliance metrics from scan results."""
    
    def __init__(self, results_dir='./scan-results'):
        self.results_dir = results_dir
        
    def collect(self):
        """Collect compliance metrics."""
        
        # Find latest scan results
        checkov_results = self._find_latest_file('checkov-*.json')
        inspec_results = self._find_latest_file('inspec-*.json')
        
        # Overall compliance metrics
        compliance_score = GaugeMetricFamily(
            'compliance_score',
            'Overall compliance score percentage',
            labels=['standard', 'environment']
        )
        
        # Control pass/fail metrics
        control_status = GaugeMetricFamily(
            'compliance_control_status',
            'Status of individual controls (1=pass, 0=fail)',
            labels=['control_id', 'severity', 'standard', 'resource_type']
        )
        
        # Violations by severity
        violations_by_severity = GaugeMetricFamily(
            'compliance_violations_severity',
            'Number of violations by severity level',
            labels=['severity', 'standard']
        )
        
        # Resource compliance
        resource_compliance = GaugeMetricFamily(
            'compliance_resource_status',
            'Compliance status by resource',
            labels=['resource_id', 'resource_type', 'status']
        )
        
        # Parse Checkov results
        if checkov_results:
            self._process_checkov(
                checkov_results,
                compliance_score,
                control_status,
                violations_by_severity,
                resource_compliance
            )
        
        # Parse InSpec results
        if inspec_results:
            self._process_inspec(
                inspec_results,
                compliance_score,
                control_status,
                violations_by_severity
            )
        
        yield compliance_score
        yield control_status
        yield violations_by_severity
        yield resource_compliance
        
        # Last scan timestamp
        last_scan = GaugeMetricFamily(
            'compliance_last_scan_timestamp',
            'Unix timestamp of last compliance scan',
            labels=['scanner']
        )
        
        if checkov_results:
            last_scan.add_metric(['checkov'], os.path.getmtime(checkov_results))
        if inspec_results:
            last_scan.add_metric(['inspec'], os.path.getmtime(inspec_results))
            
        yield last_scan
    
    def _find_latest_file(self, pattern):
        """Find the most recent file matching pattern."""
        files = glob.glob(os.path.join(self.results_dir, pattern))
        if not files:
            return None
        return max(files, key=os.path.getmtime)
    
    def _process_checkov(self, filepath, compliance_score, control_status, 
                        violations_by_severity, resource_compliance):
        """Process Checkov JSON results."""
        try:
            with open(filepath) as f:
                data = json.load(f)
            
            summary = data.get('summary', {})
            passed = summary.get('passed', 0)
            failed = summary.get('failed', 0)
            total = passed + failed
            
            if total > 0:
                score = (passed / total) * 100
                compliance_score.add_metric(['CIS-AWS', 'production'], score)
            
            # Count violations by severity
            severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            
            for result in data.get('results', {}).get('failed_checks', []):
                severity = result.get('check_class', 'MEDIUM')
                if 'CRITICAL' in severity or 'CIS_1' in severity:
                    severity_counts['CRITICAL'] += 1
                elif 'HIGH' in severity:
                    severity_counts['HIGH'] += 1
                elif 'MEDIUM' in severity:
                    severity_counts['MEDIUM'] += 1
                else:
                    severity_counts['LOW'] += 1
                
                # Individual control status
                control_status.add_metric(
                    [
                        result.get('check_id', 'unknown'),
                        severity,
                        'CIS-AWS',
                        result.get('resource', 'unknown').split('.')[0]
                    ],
                    0  # 0 = failed
                )
                
                # Resource compliance
                resource_compliance.add_metric(
                    [
                        result.get('resource', 'unknown'),
                        result.get('resource', 'unknown').split('.')[0],
                        'failed'
                    ],
                    1
                )
            
            for result in data.get('results', {}).get('passed_checks', []):
                control_status.add_metric(
                    [
                        result.get('check_id', 'unknown'),
                        'INFO',
                        'CIS-AWS',
                        result.get('resource', 'unknown').split('.')[0]
                    ],
                    1  # 1 = passed
                )
            
            for severity, count in severity_counts.items():
                violations_by_severity.add_metric([severity, 'CIS-AWS'], count)
                
        except Exception as e:
            print(f"Error processing Checkov results: {e}")
    
    def _process_inspec(self, filepath, compliance_score, control_status,
                       violations_by_severity):
        """Process InSpec JSON results."""
        try:
            with open(filepath) as f:
                data = json.load(f)
            
            profiles = data.get('profiles', [])
            
            for profile in profiles:
                controls = profile.get('controls', [])
                passed = sum(1 for c in controls if c.get('results', [{}])[0].get('status') == 'passed')
                total = len(controls)
                
                if total > 0:
                    score = (passed / total) * 100
                    standard = profile.get('name', 'CIS')
                    compliance_score.add_metric([standard, 'production'], score)
                
                # Process individual controls
                severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
                
                for control in controls:
                    control_id = control.get('id', 'unknown')
                    impact = control.get('impact', 0.5)
                    
                    # Map impact to severity
                    if impact >= 0.9:
                        severity = 'CRITICAL'
                    elif impact >= 0.7:
                        severity = 'HIGH'
                    elif impact >= 0.4:
                        severity = 'MEDIUM'
                    else:
                        severity = 'LOW'
                    
                    status = control.get('results', [{}])[0].get('status', 'failed')
                    status_value = 1 if status == 'passed' else 0
                    
                    control_status.add_metric(
                        [control_id, severity, profile.get('name', 'CIS'), 'aws'],
                        status_value
                    )
                    
                    if status != 'passed':
                        severity_counts[severity] += 1
                
                for severity, count in severity_counts.items():
                    violations_by_severity.add_metric(
                        [severity, profile.get('name', 'CIS')],
                        count
                    )
                    
        except Exception as e:
            print(f"Error processing InSpec results: {e}")


def main():
    """Main function to start the exporter."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Compliance Prometheus Exporter')
    parser.add_argument('--port', type=int, default=9090,
                       help='Port to expose metrics (default: 9090)')
    parser.add_argument('--results-dir', default='./scan-results',
                       help='Directory containing scan results')
    parser.add_argument('--interval', type=int, default=60,
                       help='Update interval in seconds (default: 60)')
    
    args = parser.parse_args()
    
    # Register collector
    REGISTRY.register(ComplianceCollector(args.results_dir))
    
    # Start HTTP server
    start_http_server(args.port)
    
    print(f"✅ Compliance metrics exporter started on port {args.port}")
    print(f"📁 Monitoring directory: {args.results_dir}")
    print(f"🔄 Update interval: {args.interval}s")
    print(f"📊 Metrics available at http://localhost:{args.port}/metrics")
    
    # Keep running
    try:
        while True:
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n👋 Exporter stopped")


if __name__ == '__main__':
    main()
