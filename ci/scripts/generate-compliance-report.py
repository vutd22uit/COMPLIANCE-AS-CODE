#!/usr/bin/env python3
"""
Generate Compliance Report
Creates a markdown compliance report from scan results.

Usage:
    python generate-compliance-report.py --checkov-results results.json --output report.md
"""

import argparse
import json
import sys
from datetime import datetime


def load_json_file(filepath):
    """Load and parse JSON file."""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Warning: File not found: {filepath}")
        return None
    except json.JSONDecodeError as e:
        print(f"Warning: Invalid JSON in {filepath}: {e}")
        return None


def generate_checkov_section(results):
    """Generate markdown section for Checkov results."""
    if not results:
        return "### Checkov Results\n\n_No Checkov results available._\n"
    
    output = ["### Checkov IaC Scan Results\n"]
    
    # Summary
    summary = results.get('summary', {})
    passed = summary.get('passed', 0)
    failed = summary.get('failed', 0)
    skipped = summary.get('skipped', 0)
    total = passed + failed + skipped
    
    pass_rate = (passed / total * 100) if total > 0 else 0
    
    output.append(f"| Metric | Count |")
    output.append(f"|--------|-------|")
    output.append(f"| ✅ Passed | {passed} |")
    output.append(f"| ❌ Failed | {failed} |")
    output.append(f"| ⏭️ Skipped | {skipped} |")
    output.append(f"| **Total** | **{total}** |")
    output.append(f"| **Pass Rate** | **{pass_rate:.1f}%** |")
    output.append("")
    
    # Failed checks
    failed_checks = results.get('results', {}).get('failed_checks', [])
    
    if failed_checks:
        output.append("#### ❌ Failed Checks\n")
        output.append("| Check ID | Resource | Guideline |")
        output.append("|----------|----------|-----------|")
        
        for check in failed_checks[:20]:  # Limit to 20
            check_id = check.get('check_id', 'N/A')
            resource = check.get('resource', 'N/A')
            guideline = check.get('guideline', check.get('check_name', 'N/A'))[:50]
            output.append(f"| {check_id} | `{resource}` | {guideline} |")
        
        if len(failed_checks) > 20:
            output.append(f"\n_...and {len(failed_checks) - 20} more failures._\n")
    
    return "\n".join(output)


def generate_summary_section(all_results):
    """Generate executive summary."""
    output = ["## 📊 Executive Summary\n"]
    
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    output.append(f"**Report Generated:** {timestamp}\n")
    
    # Calculate overall status
    total_passed = 0
    total_failed = 0
    
    for tool, results in all_results.items():
        if results and 'summary' in results:
            total_passed += results['summary'].get('passed', 0)
            total_failed += results['summary'].get('failed', 0)
    
    total = total_passed + total_failed
    overall_rate = (total_passed / total * 100) if total > 0 else 0
    
    # Status badge
    if overall_rate >= 90:
        status = "🟢 COMPLIANT"
    elif overall_rate >= 70:
        status = "🟡 NEEDS ATTENTION"
    else:
        status = "🔴 NON-COMPLIANT"
    
    output.append(f"### Overall Status: {status}\n")
    output.append(f"- **Compliance Rate:** {overall_rate:.1f}%")
    output.append(f"- **Total Checks Passed:** {total_passed}")
    output.append(f"- **Total Checks Failed:** {total_failed}")
    output.append("")
    
    return "\n".join(output)


def generate_recommendations(all_results):
    """Generate recommendations based on failures."""
    output = ["## 🔧 Recommendations\n"]
    
    recommendations = []
    
    # Analyze Checkov results
    checkov = all_results.get('checkov')
    if checkov:
        failed_checks = checkov.get('results', {}).get('failed_checks', [])
        
        # Group by category
        categories = {}
        for check in failed_checks:
            check_id = check.get('check_id', '')
            if check_id.startswith('CKV_AWS'):
                cat = 'AWS Security'
            elif check_id.startswith('CKV2'):
                cat = 'Advanced Checks'
            else:
                cat = 'General'
            
            categories[cat] = categories.get(cat, 0) + 1
        
        for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
            recommendations.append(f"- **{cat}:** {count} issues to address")
    
    if recommendations:
        output.extend(recommendations)
    else:
        output.append("✅ No critical recommendations at this time.")
    
    output.append("")
    return "\n".join(output)


def generate_report(args):
    """Generate the full compliance report."""
    all_results = {}
    
    # Load Checkov results
    if args.checkov_results:
        all_results['checkov'] = load_json_file(args.checkov_results)
    
    # Build report
    report = []
    report.append("# 🛡️ Compliance Scan Report\n")
    report.append(generate_summary_section(all_results))
    report.append("---\n")
    report.append("## 📋 Detailed Results\n")
    report.append(generate_checkov_section(all_results.get('checkov')))
    report.append("---\n")
    report.append(generate_recommendations(all_results))
    report.append("---\n")
    report.append("_Generated by Compliance-as-Code Framework_")
    
    return "\n".join(report)


def main():
    parser = argparse.ArgumentParser(description='Generate compliance report')
    parser.add_argument('--checkov-results', help='Path to Checkov JSON results')
    parser.add_argument('--inspec-results', help='Path to InSpec JSON results')
    parser.add_argument('--output', '-o', default='compliance-report.md',
                        help='Output file path')
    
    args = parser.parse_args()
    
    report = generate_report(args)
    
    with open(args.output, 'w') as f:
        f.write(report)
    
    print(f"Report generated: {args.output}")


if __name__ == '__main__':
    main()
