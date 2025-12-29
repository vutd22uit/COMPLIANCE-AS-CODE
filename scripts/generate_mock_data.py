#!/usr/bin/env python3
"""
Mock Data Generator
===================
Generates realistic fake compliance evidence for demonstration purposes.
"""

import json
import os
import random
from datetime import datetime, timezone
import uuid

EVIDENCE_DIR = "evidence_store"

CONTROLS = [
    {"id": "os-identity-1.1", "title": "Keystone Configuration Files Ownership", "severity": "MEDIUM", "section": "Identity"},
    {"id": "os-identity-1.2", "title": "Keystone Identity Provider", "severity": "HIGH", "section": "Identity"},
    {"id": "os-compute-2.1", "title": "Nova config permissions", "severity": "MEDIUM", "section": "Compute"},
    {"id": "os-networking-3.1", "title": "Neutron TLS enabled", "severity": "CRITICAL", "section": "Networking"},
    {"id": "os-networking-3.2", "title": "Neutron API limits", "severity": "LOW", "section": "Networking"},
    {"id": "os-storage-4.1", "title": "Cinder Encryption", "severity": "HIGH", "section": "Storage"},
]

def generate_mock_snapshot():
    total = 50
    passed = 38
    failed = 12
    
    snapshot = {
        "snapshot_id": f"snap-{datetime.now().strftime('%Y%m%d')}-demo",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "overall": {
            "compliance_score": 76.0,
            "total_controls": total,
            "controls_passed": passed,
            "controls_failed": failed
        },
        "by_severity": {
            "CRITICAL": {"compliance_percentage": 100, "total": 5, "passed": 5, "failed": 0},
            "HIGH": {"compliance_percentage": 60, "total": 15, "passed": 9, "failed": 6},
            "MEDIUM": {"compliance_percentage": 80, "total": 20, "passed": 16, "failed": 4},
            "LOW": {"compliance_percentage": 80, "total": 10, "passed": 8, "failed": 2}
        },
        "by_section": {
            "Identity (Keystone)": {"compliance_percentage": 85},
            "Compute (Nova)": {"compliance_percentage": 90},
            "Networking (Neutron)": {"compliance_percentage": 65},
            "Storage (Cinder)": {"compliance_percentage": 50},
        },
        "top_violations": []
    }
    
    # Generate violations
    for i in range(5):
        c = random.choice(CONTROLS)
        snapshot['top_violations'].append({
            "control_id": c['id'],
            "title": c['title'],
            "severity": c['severity'],
            "affected_resources": random.randint(1, 15)
        })
        
    return snapshot

def main():
    # Ensure dir exists
    path = os.path.join(EVIDENCE_DIR, "snapshots", "daily")
    os.makedirs(path, exist_ok=True)
    
    snapshot = generate_mock_snapshot()
    
    filename = os.path.join(path, f"{snapshot['snapshot_id']}.json")
    with open(filename, 'w') as f:
        json.dump(snapshot, f, indent=2)
        
    print(f"✅ Generated mock data: {filename}")

if __name__ == "__main__":
    main()
