#!/usr/bin/env python3
"""
Slack Webhook Integration for Compliance Alerts

Sends formatted compliance alerts to Slack channels.
Can be triggered from CI/CD or as a standalone notification tool.

Features:
- Rich message formatting with blocks
- Severity-based color coding
- Direct links to remediation docs
- Summary statistics
"""

import argparse
import json
import os
from datetime import datetime
from typing import Dict, List, Any
import logging

try:
    import requests
except ImportError:
    print("⚠️  requests library not installed. Install with: pip install requests")
    requests = None

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class SlackComplianceNotifier:
    """Sends compliance notifications to Slack."""
    
    SEVERITY_COLORS = {
        'critical': '#FF0000',
        'high': '#FF6B6B',
        'medium': '#FFD93D',
        'low': '#6BCB77'
    }
    
    SEVERITY_EMOJI = {
        'critical': '🔴',
        'high': '🟠',
        'medium': '🟡',
        'low': '🟢'
    }
    
    def __init__(self, webhook_url: str):
        """Initialize with Slack webhook URL."""
        self.webhook_url = webhook_url
        
    def send_scan_summary(self, 
                          passed: int, 
                          failed: int, 
                          skipped: int,
                          score: float,
                          failures_by_severity: Dict[str, int],
                          scan_target: str = "OpenStack",
                          report_url: str = None) -> bool:
        """
        Send a summary of compliance scan results.
        
        Returns:
            True if message sent successfully
        """
        if not requests:
            logger.error("requests library not available")
            return False
            
        total = passed + failed
        status_emoji = "✅" if score >= 80 else "⚠️" if score >= 60 else "🚨"
        
        # Build Slack blocks
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{status_emoji} Compliance Scan Complete - {scan_target}",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Score:*\n{score:.1f}%"},
                    {"type": "mrkdwn", "text": f"*Status:*\n{'PASS' if score >= 80 else 'NEEDS ATTENTION'}"},
                    {"type": "mrkdwn", "text": f"*Passed:*\n{passed}/{total}"},
                    {"type": "mrkdwn", "text": f"*Failed:*\n{failed}"}
                ]
            },
            {"type": "divider"}
        ]
        
        # Add severity breakdown if there are failures
        if failed > 0:
            severity_text = "\n".join([
                f"{self.SEVERITY_EMOJI.get(sev, '⚪')} *{sev.upper()}*: {count}"
                for sev, count in failures_by_severity.items()
                if count > 0
            ])
            
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Failures by Severity:*\n{severity_text}"
                }
            })
        
        # Add timestamp
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"📅 Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}"
                }
            ]
        })
        
        # Add report link button if available
        if report_url:
            blocks.append({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "📊 View Full Report"},
                        "url": report_url,
                        "style": "primary"
                    }
                ]
            })
        
        payload = {"blocks": blocks}
        
        try:
            response = requests.post(self.webhook_url, json=payload)
            response.raise_for_status()
            logger.info("✅ Slack notification sent successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")
            return False
    
    def send_critical_alert(self, 
                           control_id: str,
                           title: str,
                           description: str,
                           service: str) -> bool:
        """Send a critical control failure alert."""
        if not requests:
            return False
            
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🚨 CRITICAL Compliance Failure",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Control:* `{control_id}`\n*Service:* {service}\n*Title:* {title}"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Description:*\n{description[:500]}..."
                }
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"🕐 Detected at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                    }
                ]
            }
        ]
        
        payload = {
            "blocks": blocks,
            "attachments": [{"color": "#FF0000"}]
        }
        
        try:
            response = requests.post(self.webhook_url, json=payload)
            response.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"Failed to send alert: {e}")
            return False


def process_results_and_notify(results_file: str, webhook_url: str, report_url: str = None):
    """Process InSpec results and send Slack notification."""
    with open(results_file, 'r') as f:
        data = json.load(f)
    
    passed = 0
    failed = 0
    skipped = 0
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    critical_failures = []
    
    for profile in data.get('profiles', []):
        for control in profile.get('controls', []):
            results = control.get('results', [])
            has_failure = any(r.get('status') == 'failed' for r in results)
            has_pass = any(r.get('status') == 'passed' for r in results)
            
            # Get severity
            impact = control.get('impact', 0.5)
            if impact >= 0.9:
                severity = 'critical'
            elif impact >= 0.7:
                severity = 'high'
            elif impact >= 0.4:
                severity = 'medium'
            else:
                severity = 'low'
            
            if has_failure:
                failed += 1
                severity_counts[severity] += 1
                
                if severity == 'critical':
                    critical_failures.append({
                        'id': control.get('id'),
                        'title': control.get('title', ''),
                        'desc': control.get('desc', '')
                    })
            elif has_pass:
                passed += 1
            else:
                skipped += 1
    
    total = passed + failed
    score = (passed / total * 100) if total > 0 else 0
    
    notifier = SlackComplianceNotifier(webhook_url)
    
    # Send summary
    notifier.send_scan_summary(
        passed=passed,
        failed=failed,
        skipped=skipped,
        score=score,
        failures_by_severity=severity_counts,
        report_url=report_url
    )
    
    # Send individual alerts for critical failures
    for failure in critical_failures[:3]:  # Limit to 3 to avoid spam
        notifier.send_critical_alert(
            control_id=failure['id'],
            title=failure['title'],
            description=failure['desc'],
            service='OpenStack'
        )


def main():
    parser = argparse.ArgumentParser(description='Send compliance notifications to Slack')
    parser.add_argument('--results', required=True, help='Path to InSpec JSON results')
    parser.add_argument('--webhook-url', default=os.environ.get('SLACK_WEBHOOK_URL'),
                       help='Slack webhook URL (or set SLACK_WEBHOOK_URL env var)')
    parser.add_argument('--report-url', help='Optional URL to full report')
    parser.add_argument('--test', action='store_true', help='Send a test message')
    
    args = parser.parse_args()
    
    if not requests:
        print("❌ Error: requests library required. Install with: pip install requests")
        exit(1)
    
    if not args.webhook_url:
        print("❌ Error: Slack webhook URL required.")
        print("Set via --webhook-url or SLACK_WEBHOOK_URL environment variable")
        exit(1)
    
    if args.test:
        notifier = SlackComplianceNotifier(args.webhook_url)
        notifier.send_scan_summary(
            passed=42,
            failed=3,
            skipped=2,
            score=93.3,
            failures_by_severity={'critical': 0, 'high': 1, 'medium': 2, 'low': 0},
            scan_target="OpenStack (TEST)"
        )
        print("✅ Test message sent!")
        exit(0)
    
    process_results_and_notify(args.results, args.webhook_url, args.report_url)


if __name__ == '__main__':
    main()
