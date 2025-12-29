#!/usr/bin/env python3
"""
Simulate Incident Script for Demo
---------------------------------
This script manipulates the mock data generation to toggle between 
a 'Compliant' (Green) state and a 'Broken' (Red) state.

Usage:
    python3 scripts/simulate_incident.py --break  # Drop compliance score
    python3 scripts/simulate_incident.py --fix    # Restore compliance score
"""

import argparse
import json
import os
import random
import time
from datetime import datetime, timezone

# Configuration
RESULTS_DIR = "./scan-results"
EVIDENCE_DIR = "./evidence_store/snapshots/daily"

def ensure_dirs():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    os.makedirs(EVIDENCE_DIR, exist_ok=True)

def generate_scan_result(is_broken: bool):
    """Generates a scan result file."""
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    filename = f"openstack-cis-{int(time.time())}.json"
    filepath = os.path.join(RESULTS_DIR, filename)

    # Base counts
    total_controls = 88
    
    if is_broken:
        # Scenario: Major Incidents
        # - SSH open to world
        # - Unencrypted volumes
        # - Weak passwords
        passed = random.randint(45, 55)  # ~50-60% score
        failed = total_controls - passed
        print(f"🔥 SIMULATING INCIDENT...")
        print(f"Creating critical failures: SSH Open, No TLS, Weak Auth...")
    else:
        # Scenario: Compliant State
        passed = random.randint(85, 88)  # ~96-100% score
        failed = total_controls - passed
        print(f"✅ SIMULATING REMEDIATION...")
        print(f"Restoring security controls...")

    # Create dummy controls structure
    controls = []
    
    # Add passed controls
    for i in range(passed):
        controls.append({
            "id": f"CIS-OS-{i+1}",
            "title": f"Compliant Control {i+1}",
            "desc": "This control is compliant.",
            "impact": 0.5,
            "tags": {"severity": "medium"},
            "results": [{"status": "passed", "code_desc": "Check passed"}]
        })

    # Add failed controls
    critical_titles = [
        "Ensure SSH is not open to the world",
        "Ensure TLS is enabled for Keystone",
        "Ensure Cinder volumes are encrypted",
        "Ensure default security group is restricted",
        "Ensure root login is disabled"
    ]
    
    for i in range(failed):
        title = critical_titles[i % len(critical_titles)] if is_broken else f"Failed Control {i+1}"
        severity = "critical" if is_broken else "low"
        impact = 1.0 if is_broken else 0.3
        
        controls.append({
            "id": f"CIS-OS-FAIL-{i+1}",
            "title": title,
            "desc": "This control has failed validation.",
            "impact": impact,
            "tags": {"severity": severity},
            "results": [{"status": "failed", "code_desc": "Check failed"}]
        })

    data = {
        "platform": {"name": "openstack", "release": "yoga"},
        "profiles": [{
            "name": "openstack-cis",
            "version": "1.0.0",
            "controls": controls
        }],
        "statistics": {
            "duration": 4.5
        },
        "version": "5.22.0"
    }

    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"📄 Generated scan result: {filepath}")
    
    score = (passed / total_controls) * 100
    print(f"📊 New Score: {score:.1f}%")
    
    # Also create a baseline if fixing
    if not is_broken:
         baseline_path = "./baselines/current-baseline.json"
         os.makedirs("./baselines", exist_ok=True)
         with open(baseline_path, 'w') as f:
             json.dump(data, f, indent=2)

def main():
    parser = argparse.ArgumentParser(description='Simulate incident/fix for demo')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--break', dest='do_break', action='store_true', help='Simulate a compliance incident')
    group.add_argument('--fix', dest='do_fix', action='store_true', help='Simulate remediation')
    
    args = parser.parse_args()
    
    ensure_dirs()
    generate_scan_result(args.do_break)

if __name__ == '__main__':
    main()
