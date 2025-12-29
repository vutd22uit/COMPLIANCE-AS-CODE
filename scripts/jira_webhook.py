#!/usr/bin/env python3
"""
JIRA Integration for Compliance Findings

Automatically creates JIRA tickets for failed compliance controls.
Can be triggered manually or integrated with CI/CD pipelines.

Features:
- Creates tickets for new failures
- Updates existing tickets for recurring failures
- Closes tickets when issues are remediated
- Supports priority mapping based on control severity
"""

import argparse
import json
import os
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging

# Try to import requests, provide helpful message if not installed
try:
    import requests
except ImportError:
    print("⚠️  requests library not installed. Install with: pip install requests")
    requests = None

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class JiraComplianceIntegration:
    """Handles JIRA ticket creation for compliance findings."""
    
    def __init__(self, 
                 jira_url: str,
                 username: str,
                 api_token: str,
                 project_key: str,
                 issue_type: str = "Bug"):
        """
        Initialize JIRA integration.
        
        Args:
            jira_url: JIRA instance URL (e.g., https://your-domain.atlassian.net)
            username: JIRA username (email)
            api_token: JIRA API token
            project_key: JIRA project key (e.g., SEC)
            issue_type: Issue type for tickets (default: Bug)
        """
        self.jira_url = jira_url.rstrip('/')
        self.username = username
        self.api_token = api_token
        self.project_key = project_key
        self.issue_type = issue_type
        self.session = requests.Session() if requests else None
        
        if self.session:
            self.session.auth = (username, api_token)
            self.session.headers.update({
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            })
    
    def _get_control_hash(self, control_id: str) -> str:
        """Generate unique hash for a control to track tickets."""
        return hashlib.md5(f"compliance:{control_id}".encode()).hexdigest()[:8]
    
    def _severity_to_priority(self, severity: str) -> str:
        """Map compliance severity to JIRA priority."""
        mapping = {
            'critical': 'Highest',
            'high': 'High',
            'medium': 'Medium',
            'low': 'Low'
        }
        return mapping.get(severity.lower(), 'Medium')
    
    def _search_existing_ticket(self, control_id: str) -> Optional[Dict]:
        """Search for existing ticket for this control."""
        if not self.session:
            return None
            
        jql = f'project = {self.project_key} AND labels = compliance-{self._get_control_hash(control_id)} AND status != Done'
        
        try:
            response = self.session.get(
                f"{self.jira_url}/rest/api/3/search",
                params={'jql': jql, 'maxResults': 1}
            )
            response.raise_for_status()
            data = response.json()
            
            if data.get('issues'):
                return data['issues'][0]
            return None
        except Exception as e:
            logger.error(f"Failed to search JIRA: {e}")
            return None
    
    def create_ticket(self, 
                     control_id: str,
                     title: str,
                     description: str,
                     severity: str,
                     service: str,
                     scan_date: str) -> Optional[str]:
        """
        Create a JIRA ticket for a failed control.
        
        Returns:
            Ticket key (e.g., SEC-123) or None if failed
        """
        if not self.session:
            logger.warning("JIRA session not available (requests not installed)")
            return None
        
        # Check for existing ticket
        existing = self._search_existing_ticket(control_id)
        if existing:
            logger.info(f"Ticket already exists: {existing['key']}")
            return self._update_ticket(existing['key'], scan_date)
        
        # Build ticket payload
        control_hash = self._get_control_hash(control_id)
        
        payload = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": f"[Compliance] {control_id}: {title[:80]}",
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [{"type": "text", "text": description}]
                        },
                        {
                            "type": "paragraph",
                            "content": [
                                {"type": "text", "text": f"\n\n📌 Control ID: {control_id}\n"},
                                {"type": "text", "text": f"🎯 Service: {service}\n"},
                                {"type": "text", "text": f"⚠️ Severity: {severity.upper()}\n"},
                                {"type": "text", "text": f"📅 Detected: {scan_date}\n"}
                            ]
                        }
                    ]
                },
                "issuetype": {"name": self.issue_type},
                "priority": {"name": self._severity_to_priority(severity)},
                "labels": [
                    "compliance",
                    f"compliance-{control_hash}",
                    f"service-{service}",
                    f"severity-{severity.lower()}"
                ]
            }
        }
        
        try:
            response = self.session.post(
                f"{self.jira_url}/rest/api/3/issue",
                json=payload
            )
            response.raise_for_status()
            ticket_key = response.json().get('key')
            logger.info(f"✅ Created ticket: {ticket_key}")
            return ticket_key
        except Exception as e:
            logger.error(f"Failed to create JIRA ticket: {e}")
            return None
    
    def _update_ticket(self, ticket_key: str, scan_date: str) -> str:
        """Add a comment to existing ticket noting recurrence."""
        if not self.session:
            return ticket_key
            
        comment_payload = {
            "body": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [
                            {
                                "type": "text",
                                "text": f"🔄 This issue was detected again during compliance scan on {scan_date}."
                            }
                        ]
                    }
                ]
            }
        }
        
        try:
            self.session.post(
                f"{self.jira_url}/rest/api/3/issue/{ticket_key}/comment",
                json=comment_payload
            )
            logger.info(f"📝 Updated ticket with new detection: {ticket_key}")
        except Exception as e:
            logger.warning(f"Failed to add comment to {ticket_key}: {e}")
        
        return ticket_key
    
    def close_ticket(self, control_id: str) -> bool:
        """Close ticket when control is remediated."""
        if not self.session:
            return False
            
        existing = self._search_existing_ticket(control_id)
        if not existing:
            return True  # No ticket to close
        
        ticket_key = existing['key']
        
        # Get available transitions
        try:
            response = self.session.get(
                f"{self.jira_url}/rest/api/3/issue/{ticket_key}/transitions"
            )
            response.raise_for_status()
            transitions = response.json().get('transitions', [])
            
            # Find "Done" or "Resolved" transition
            close_transition = None
            for t in transitions:
                if t['name'].lower() in ['done', 'resolved', 'closed']:
                    close_transition = t['id']
                    break
            
            if close_transition:
                self.session.post(
                    f"{self.jira_url}/rest/api/3/issue/{ticket_key}/transitions",
                    json={"transition": {"id": close_transition}}
                )
                logger.info(f"✅ Closed ticket: {ticket_key}")
                return True
            else:
                logger.warning(f"No close transition found for {ticket_key}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to close ticket {ticket_key}: {e}")
            return False


def process_scan_results(results_file: str, jira: JiraComplianceIntegration) -> Dict[str, int]:
    """
    Process InSpec scan results and create JIRA tickets for failures.
    
    Returns:
        Dictionary with created/updated/closed ticket counts
    """
    with open(results_file, 'r') as f:
        data = json.load(f)
    
    stats = {'created': 0, 'updated': 0, 'closed': 0, 'errors': 0}
    scan_date = datetime.now().strftime('%Y-%m-%d %H:%M')
    
    profiles = data.get('profiles', [])
    
    for profile in profiles:
        for control in profile.get('controls', []):
            control_id = control.get('id', 'unknown')
            title = control.get('title', 'No title')
            description = control.get('desc', control.get('title', ''))
            results = control.get('results', [])
            
            # Determine status
            has_failure = any(r.get('status') == 'failed' for r in results)
            
            # Get severity
            severity = control.get('tags', {}).get('severity', '')
            if not severity:
                impact = control.get('impact', 0.5)
                if impact >= 0.9:
                    severity = 'critical'
                elif impact >= 0.7:
                    severity = 'high'
                elif impact >= 0.4:
                    severity = 'medium'
                else:
                    severity = 'low'
            
            # Get service
            service = 'unknown'
            if 'identity' in control_id.lower():
                service = 'keystone'
            elif 'compute' in control_id.lower():
                service = 'nova'
            elif 'networking' in control_id.lower():
                service = 'neutron'
            elif 'storage' in control_id.lower():
                service = 'cinder'
            elif 'image' in control_id.lower():
                service = 'glance'
            elif 'dashboard' in control_id.lower():
                service = 'horizon'
            elif 'orchestration' in control_id.lower():
                service = 'heat'
            elif control_id.lower().startswith('cis-'):
                service = 'linux'
            
            if has_failure:
                # Create or update ticket
                result = jira.create_ticket(
                    control_id=control_id,
                    title=title,
                    description=description,
                    severity=severity,
                    service=service,
                    scan_date=scan_date
                )
                if result:
                    stats['created'] += 1
                else:
                    stats['errors'] += 1
            else:
                # Close any existing ticket
                if jira.close_ticket(control_id):
                    stats['closed'] += 1
    
    return stats


def main():
    parser = argparse.ArgumentParser(
        description='Create JIRA tickets for compliance findings'
    )
    parser.add_argument('--results', required=True, help='Path to InSpec JSON results')
    parser.add_argument('--jira-url', default=os.environ.get('JIRA_URL'), 
                       help='JIRA URL (or set JIRA_URL env var)')
    parser.add_argument('--username', default=os.environ.get('JIRA_USERNAME'),
                       help='JIRA username (or set JIRA_USERNAME env var)')
    parser.add_argument('--api-token', default=os.environ.get('JIRA_API_TOKEN'),
                       help='JIRA API token (or set JIRA_API_TOKEN env var)')
    parser.add_argument('--project', default=os.environ.get('JIRA_PROJECT', 'SEC'),
                       help='JIRA project key (default: SEC)')
    parser.add_argument('--dry-run', action='store_true',
                       help='Print what would be done without creating tickets')
    
    args = parser.parse_args()
    
    if not requests:
        print("❌ Error: requests library is required. Install with: pip install requests")
        exit(1)
    
    if not all([args.jira_url, args.username, args.api_token]):
        print("❌ Error: JIRA credentials required.")
        print("Set via arguments or environment variables:")
        print("  JIRA_URL, JIRA_USERNAME, JIRA_API_TOKEN")
        exit(1)
    
    if args.dry_run:
        print("🧪 DRY-RUN MODE - No tickets will be created\n")
        
        # Just parse and show what would be created
        with open(args.results, 'r') as f:
            data = json.load(f)
        
        failures = []
        for profile in data.get('profiles', []):
            for control in profile.get('controls', []):
                results = control.get('results', [])
                if any(r.get('status') == 'failed' for r in results):
                    failures.append({
                        'id': control.get('id'),
                        'title': control.get('title', '')[:60],
                        'impact': control.get('impact', 0.5)
                    })
        
        print(f"📋 Would create {len(failures)} ticket(s):\n")
        for f in failures:
            print(f"  • [{f['id']}] {f['title']}...")
        
        exit(0)
    
    # Initialize JIRA integration
    jira = JiraComplianceIntegration(
        jira_url=args.jira_url,
        username=args.username,
        api_token=args.api_token,
        project_key=args.project
    )
    
    print(f"📊 Processing scan results: {args.results}")
    stats = process_scan_results(args.results, jira)
    
    print("\n" + "="*50)
    print("📈 JIRA INTEGRATION SUMMARY")
    print("="*50)
    print(f"✅ Tickets created/updated: {stats['created']}")
    print(f"🔒 Tickets closed (remediated): {stats['closed']}")
    print(f"❌ Errors: {stats['errors']}")
    print("="*50)


if __name__ == '__main__':
    main()
