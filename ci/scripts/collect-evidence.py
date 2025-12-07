#!/usr/bin/env python3
"""
Collect Compliance Evidence
Collects and stores compliance scan evidence for audit purposes.

Usage:
    python collect-evidence.py --scan-dir ./results --output-dir ./evidence
"""

import argparse
import hashlib
import json
import os
import shutil
from datetime import datetime


def compute_hash(filepath):
    """Compute SHA256 hash of file."""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sha256.update(chunk)
    return sha256.hexdigest()


def collect_evidence(scan_dir, output_dir):
    """Collect and organize evidence files."""
    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    evidence_path = os.path.join(output_dir, timestamp)
    os.makedirs(evidence_path, exist_ok=True)
    
    manifest = {
        "collection_timestamp": datetime.utcnow().isoformat(),
        "scan_directory": os.path.abspath(scan_dir),
        "files": []
    }
    
    # Collect all result files
    for root, dirs, files in os.walk(scan_dir):
        for filename in files:
            if filename.endswith(('.json', '.sarif', '.xml', '.html')):
                src_path = os.path.join(root, filename)
                rel_path = os.path.relpath(src_path, scan_dir)
                dst_path = os.path.join(evidence_path, rel_path)
                
                os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                shutil.copy2(src_path, dst_path)
                
                manifest["files"].append({
                    "filename": rel_path,
                    "sha256": compute_hash(src_path),
                    "size_bytes": os.path.getsize(src_path),
                    "collected_at": datetime.utcnow().isoformat()
                })
                
                print(f"Collected: {rel_path}")
    
    # Write manifest
    manifest_path = os.path.join(evidence_path, "manifest.json")
    with open(manifest_path, 'w') as f:
        json.dump(manifest, f, indent=2)
    
    print(f"\nEvidence collected: {evidence_path}")
    print(f"Total files: {len(manifest['files'])}")
    
    return evidence_path


def main():
    parser = argparse.ArgumentParser(description='Collect compliance evidence')
    parser.add_argument('--scan-dir', required=True, help='Directory with scan results')
    parser.add_argument('--output-dir', default='./evidence', help='Output directory')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.scan_dir):
        print(f"Error: Scan directory not found: {args.scan_dir}")
        return 1
    
    collect_evidence(args.scan_dir, args.output_dir)
    return 0


if __name__ == '__main__':
    exit(main())
