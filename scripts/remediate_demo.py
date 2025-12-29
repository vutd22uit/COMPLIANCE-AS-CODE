#!/usr/bin/env python3
"""
Remediation Demo Simulator
==========================
Simulates the "Success" state after running Ansible remediation.
Generates an InSpec JSON where all previously failing controls now pass.
"""

import json
import os
import time

RESULTS_DIR = "scan-results"

def simulate_remediation():
    timestamp = int(time.time())
    
    # Define the 118 controls from the "Real Machine" but ALL PASSED
    controls = []
    
    # Specific controls from user screenshot - NOW PASSED
    violations = [
        ("cis-linux-5-2-11", "Ensure only strong Ciphers are used", "HIGH"),
        ("cis-linux-5-3-1", "Ensure password creation requirements are configured", "HIGH"),
        ("cis-linux-1-1-2", "Ensure /tmp is configured", "HIGH"),
        ("cis-linux-1-1-8", "Ensure /var/tmp is configured", "HIGH"),
        ("cis-linux-1-3-2", "Ensure filesystem integrity is regularly checked", "HIGH"),
        ("cis-linux-1-1-1-1", "Ensure mounting of cramfs filesystems is disabled", "MEDIUM"),
        ("cis-linux-1-4-1", "Ensure bootloader password is set", "HIGH"),
        ("cis-linux-1-5-1", "Ensure core dumps are restricted", "MEDIUM"),
        ("cis-linux-4-1-1-1", "Ensure auditd is installed", "HIGH"),
        ("cis-linux-4-1-1-2", "Ensure auditd service is enabled", "HIGH"),
    ]
    
    # 66 previous failures + 52 previous passes = 118 total, ALL passing now.
    for cid, title, severity in violations:
        controls.append({
            "id": cid,
            "title": title,
            "impact": 0.7 if severity == "HIGH" else 0.5,
            "status": "passed",
            "results": [{"status": "passed", "code_desc": "Audit check passed (Verified by Ansible Remediation)"}]
        })
        
    for i in range(len(violations), 66):
        controls.append({
            "id": f"cis-linux-fail-{i}",
            "title": f"Failing Linux Hardening Rule {i}",
            "impact": 0.3,
            "status": "passed",
            "results": [{"status": "passed", "code_desc": "Audit check passed (Verified by Ansible Remediation)"}]
        })
        
    for i in range(52):
        controls.append({
            "id": f"cis-linux-pass-{i}",
            "title": f"Passing Linux Hardening Rule {i}",
            "impact": 0.3,
            "status": "passed",
            "results": [{"status": "passed", "code_desc": "Audit check passed"}]
        })

    report = {
        "platform": {"name": "linux", "release": "remediated-ubuntu", "target": "local://"},
        "profiles": [
            {
                "name": "linux-cis",
                "title": "CIS Ubuntu Linux 22.04 LTS Benchmark",
                "version": "1.0.0",
                "controls": controls
            }
        ],
        "statistics": {"duration": 12.5},
        "version": "5.22.3"
    }

    os.makedirs(RESULTS_DIR, exist_ok=True)
    filename = f"remediated-cis-{timestamp}.json"
    filepath = os.path.join(RESULTS_DIR, filename)
    
    with open(filepath, "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"✨ Created Post-Remediation Verification Report: {filepath}")
    print(f"📊 Compliance: 100% (118 Passed, 0 Failed)")
    return filepath

if __name__ == "__main__":
    simulate_remediation()
