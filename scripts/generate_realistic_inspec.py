#!/usr/bin/env python3
"""
High-Fidelity InSpec JSON Simulator - REAL MACHINE DATA
======================================================
Generates InSpec-formatted JSON results based on the "Real Machine" 
provided by the user in the screenshot (44.07% compliance).
"""

import json
import os
import time
import random

RESULTS_DIR = "scan-results"

def generate_real_machine_data():
    # Use CURRENT time as seconds
    # To fix "65 years" (1970) issue: 
    # If Grafana scale is milliseconds, 1.7B seconds looks like 1970.
    # We will provide seconds and fix Grafana unit to 's' (seconds) or ensure exporters handle it.
    timestamp_seconds = int(time.time())
    
    # Data from user image:
    # 52 passed, 66 failed = 118 total (Wait, image says 60 checked but 52 passed/66 failed?)
    # Score 44.07% suggests roughly 52/118? No, 52/118 = 44.067%. 
    # YES! The image score 44.07% = 52 Passed / (52 Passed + 66 Failed).
    
    # Specifically list the "Top Violations" from the image
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
    
    controls = []
    
    # Add the specific failures from the image
    for cid, title, severity in violations:
        impact = 0.7 if severity == "HIGH" else 0.5
        controls.append({
            "id": cid,
            "title": title,
            "impact": impact,
            "status": "failed",
            "results": [{"status": "failed", "code_desc": "Audit check failed"}]
        })
        
    # Add more failures to reach 66 failed
    for i in range(len(violations), 66):
        controls.append({
            "id": f"cis-linux-fail-{i}",
            "title": f"Failing Linux Hardening Rule {i}",
            "impact": 0.3,
            "status": "failed",
            "results": [{"status": "failed", "code_desc": "Audit check failed"}]
        })
        
    # Add 52 passed to reach total 118
    for i in range(52):
        controls.append({
            "id": f"cis-linux-pass-{i}",
            "title": f"Passing Linux Hardening Rule {i}",
            "impact": 0.3,
            "status": "passed",
            "results": [{"status": "passed", "code_desc": "Audit check passed"}]
        })

    report = {
        "platform": {"name": "linux", "release": "ubuntu-22.04", "target": "local://"},
        "profiles": [
            {
                "name": "linux-cis",
                "title": "CIS Ubuntu Linux 22.04 LTS Benchmark",
                "version": "1.0.0",
                "controls": controls
            }
        ],
        "statistics": {"duration": 45.2},
        "version": "5.22.3"
    }

    os.makedirs(RESULTS_DIR, exist_ok=True)
    filename = f"openstack-cis-{timestamp_seconds}.json"
    filepath = os.path.join(RESULTS_DIR, filename)
    
    with open(filepath, "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"✅ Generated real machine simulation: {filepath}")
    print(f"📊 Compliance: 44.07% (52 Passed, 66 Failed)")
    return filepath

if __name__ == "__main__":
    generate_real_machine_data()
