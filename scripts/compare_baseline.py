#!/usr/bin/env python3
"""
Compliance Baseline Comparison Tool

Compares current InSpec scan results with a baseline to identify:
- New failures (regressions)
- Fixed issues (improvements)
- Unchanged status

Generates an HTML diff report.
"""

import argparse
import json
import os
from datetime import datetime
from typing import Dict, List, Any, Tuple

def load_inspec_results(filepath: str) -> Dict[str, Any]:
    """Load and parse InSpec JSON results."""
    with open(filepath, 'r') as f:
        return json.load(f)

def extract_control_statuses(data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Extract control statuses from InSpec results."""
    controls = {}
    
    profiles = data.get('profiles', [])
    for profile in profiles:
        for control in profile.get('controls', []):
            control_id = control.get('id', 'unknown')
            title = control.get('title', '')
            results = control.get('results', [])
            
            # Determine status
            has_failure = any(r.get('status') == 'failed' for r in results)
            has_pass = any(r.get('status') == 'passed' for r in results)
            
            if has_failure:
                status = 'FAIL'
            elif has_pass:
                status = 'PASS'
            else:
                status = 'SKIP'
            
            controls[control_id] = {
                'title': title,
                'status': status,
                'impact': control.get('impact', 0.5)
            }
    
    return controls

def compare_controls(baseline: Dict[str, Dict], current: Dict[str, Dict]) -> Tuple[List, List, List, List]:
    """
    Compare baseline and current controls.
    
    Returns:
        - regressions: Controls that went from PASS to FAIL
        - improvements: Controls that went from FAIL to PASS
        - new_controls: Controls in current but not in baseline
        - removed_controls: Controls in baseline but not in current
    """
    regressions = []
    improvements = []
    new_controls = []
    removed_controls = []
    
    all_ids = set(baseline.keys()) | set(current.keys())
    
    for control_id in all_ids:
        base = baseline.get(control_id)
        curr = current.get(control_id)
        
        if base is None:
            new_controls.append({
                'id': control_id,
                'title': curr.get('title', ''),
                'status': curr.get('status', 'UNKNOWN'),
                'impact': curr.get('impact', 0.5)
            })
        elif curr is None:
            removed_controls.append({
                'id': control_id,
                'title': base.get('title', ''),
                'status': base.get('status', 'UNKNOWN'),
                'impact': base.get('impact', 0.5)
            })
        else:
            base_status = base.get('status')
            curr_status = curr.get('status')
            
            if base_status == 'PASS' and curr_status == 'FAIL':
                regressions.append({
                    'id': control_id,
                    'title': curr.get('title', ''),
                    'previous': base_status,
                    'current': curr_status,
                    'impact': curr.get('impact', 0.5)
                })
            elif base_status == 'FAIL' and curr_status == 'PASS':
                improvements.append({
                    'id': control_id,
                    'title': curr.get('title', ''),
                    'previous': base_status,
                    'current': curr_status,
                    'impact': curr.get('impact', 0.5)
                })
    
    # Sort by impact (highest first)
    regressions.sort(key=lambda x: -x['impact'])
    improvements.sort(key=lambda x: -x['impact'])
    
    return regressions, improvements, new_controls, removed_controls

def calculate_statistics(baseline: Dict, current: Dict) -> Dict[str, Any]:
    """Calculate comparison statistics."""
    base_passed = sum(1 for c in baseline.values() if c['status'] == 'PASS')
    base_failed = sum(1 for c in baseline.values() if c['status'] == 'FAIL')
    curr_passed = sum(1 for c in current.values() if c['status'] == 'PASS')
    curr_failed = sum(1 for c in current.values() if c['status'] == 'FAIL')
    
    base_total = base_passed + base_failed
    curr_total = curr_passed + curr_failed
    
    base_score = (base_passed / base_total * 100) if base_total > 0 else 0
    curr_score = (curr_passed / curr_total * 100) if curr_total > 0 else 0
    
    return {
        'baseline': {
            'passed': base_passed,
            'failed': base_failed,
            'total': len(baseline),
            'score': round(base_score, 2)
        },
        'current': {
            'passed': curr_passed,
            'failed': curr_failed,
            'total': len(current),
            'score': round(curr_score, 2)
        },
        'delta': {
            'passed': curr_passed - base_passed,
            'failed': curr_failed - base_failed,
            'score': round(curr_score - base_score, 2)
        }
    }

def generate_html_report(
    stats: Dict,
    regressions: List,
    improvements: List,
    new_controls: List,
    removed_controls: List,
    baseline_file: str,
    current_file: str
) -> str:
    """Generate HTML comparison report."""
    
    delta_color = 'green' if stats['delta']['score'] >= 0 else 'red'
    delta_icon = '📈' if stats['delta']['score'] >= 0 else '📉'
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Compliance Baseline Comparison Report</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-card: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent-green: #22c55e;
            --accent-red: #ef4444;
            --accent-yellow: #eab308;
            --accent-blue: #3b82f6;
            --gradient-1: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }}
        
        header {{
            background: var(--gradient-1);
            padding: 3rem 2rem;
            text-align: center;
            border-radius: 1rem;
            margin-bottom: 2rem;
        }}
        
        h1 {{
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }}
        
        .subtitle {{
            color: rgba(255,255,255,0.8);
            font-size: 1.1rem;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}
        
        .stat-card {{
            background: var(--bg-secondary);
            border-radius: 1rem;
            padding: 1.5rem;
            border: 1px solid rgba(255,255,255,0.1);
        }}
        
        .stat-card h3 {{
            color: var(--text-secondary);
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 1rem;
        }}
        
        .stat-value {{
            font-size: 3rem;
            font-weight: 700;
        }}
        
        .stat-value.green {{ color: var(--accent-green); }}
        .stat-value.red {{ color: var(--accent-red); }}
        .stat-value.blue {{ color: var(--accent-blue); }}
        
        .stat-detail {{
            color: var(--text-secondary);
            font-size: 0.875rem;
            margin-top: 0.5rem;
        }}
        
        .section {{
            background: var(--bg-secondary);
            border-radius: 1rem;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            border: 1px solid rgba(255,255,255,0.1);
        }}
        
        .section h2 {{
            font-size: 1.25rem;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        
        .badge {{
            display: inline-flex;
            align-items: center;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
        }}
        
        .badge.red {{ background: rgba(239,68,68,0.2); color: var(--accent-red); }}
        .badge.green {{ background: rgba(34,197,94,0.2); color: var(--accent-green); }}
        .badge.blue {{ background: rgba(59,130,246,0.2); color: var(--accent-blue); }}
        .badge.yellow {{ background: rgba(234,179,8,0.2); color: var(--accent-yellow); }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        th, td {{
            padding: 0.75rem 1rem;
            text-align: left;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }}
        
        th {{
            color: var(--text-secondary);
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        
        tr:hover {{
            background: rgba(255,255,255,0.05);
        }}
        
        .empty-state {{
            text-align: center;
            padding: 2rem;
            color: var(--text-secondary);
        }}
        
        .meta {{
            margin-top: 2rem;
            padding: 1rem;
            background: var(--bg-card);
            border-radius: 0.5rem;
            font-size: 0.875rem;
            color: var(--text-secondary);
        }}
        
        .impact-high {{ color: var(--accent-red); }}
        .impact-medium {{ color: var(--accent-yellow); }}
        .impact-low {{ color: var(--accent-green); }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>📊 Compliance Baseline Comparison</h1>
            <p class="subtitle">Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </header>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Baseline Score</h3>
                <div class="stat-value blue">{stats['baseline']['score']}%</div>
                <div class="stat-detail">{stats['baseline']['passed']} passed / {stats['baseline']['total']} total</div>
            </div>
            
            <div class="stat-card">
                <h3>Current Score</h3>
                <div class="stat-value blue">{stats['current']['score']}%</div>
                <div class="stat-detail">{stats['current']['passed']} passed / {stats['current']['total']} total</div>
            </div>
            
            <div class="stat-card">
                <h3>Score Change {delta_icon}</h3>
                <div class="stat-value {delta_color}">{'+' if stats['delta']['score'] >= 0 else ''}{stats['delta']['score']}%</div>
                <div class="stat-detail">
                    {'+' if stats['delta']['passed'] >= 0 else ''}{stats['delta']['passed']} passed controls
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>🔴 Regressions <span class="badge red">{len(regressions)}</span></h2>
            {'<p class="empty-state">No regressions detected! ✨</p>' if not regressions else f'''
            <table>
                <thead>
                    <tr>
                        <th>Control ID</th>
                        <th>Title</th>
                        <th>Impact</th>
                        <th>Change</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(f'''
                    <tr>
                        <td><code>{r['id']}</code></td>
                        <td>{r['title'][:60]}...</td>
                        <td class="{'impact-high' if r['impact'] >= 0.7 else 'impact-medium' if r['impact'] >= 0.4 else 'impact-low'}">{r['impact']}</td>
                        <td><span class="badge green">PASS</span> → <span class="badge red">FAIL</span></td>
                    </tr>
                    ''' for r in regressions)}
                </tbody>
            </table>
            '''}
        </div>
        
        <div class="section">
            <h2>🟢 Improvements <span class="badge green">{len(improvements)}</span></h2>
            {'<p class="empty-state">No improvements since baseline.</p>' if not improvements else f'''
            <table>
                <thead>
                    <tr>
                        <th>Control ID</th>
                        <th>Title</th>
                        <th>Impact</th>
                        <th>Change</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(f'''
                    <tr>
                        <td><code>{r['id']}</code></td>
                        <td>{r['title'][:60]}...</td>
                        <td class="{'impact-high' if r['impact'] >= 0.7 else 'impact-medium' if r['impact'] >= 0.4 else 'impact-low'}">{r['impact']}</td>
                        <td><span class="badge red">FAIL</span> → <span class="badge green">PASS</span></td>
                    </tr>
                    ''' for r in improvements)}
                </tbody>
            </table>
            '''}
        </div>
        
        <div class="section">
            <h2>🆕 New Controls <span class="badge blue">{len(new_controls)}</span></h2>
            {'<p class="empty-state">No new controls added.</p>' if not new_controls else f'''
            <table>
                <thead>
                    <tr>
                        <th>Control ID</th>
                        <th>Title</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(f'''
                    <tr>
                        <td><code>{c['id']}</code></td>
                        <td>{c['title'][:60]}...</td>
                        <td><span class="badge {'green' if c['status'] == 'PASS' else 'red' if c['status'] == 'FAIL' else 'yellow'}">{c['status']}</span></td>
                    </tr>
                    ''' for c in new_controls)}
                </tbody>
            </table>
            '''}
        </div>
        
        <div class="meta">
            <strong>Baseline:</strong> {os.path.basename(baseline_file)}<br>
            <strong>Current:</strong> {os.path.basename(current_file)}
        </div>
    </div>
</body>
</html>
"""
    return html

def main():
    parser = argparse.ArgumentParser(description='Compare compliance scan results with baseline')
    parser.add_argument('--baseline', required=True, help='Path to baseline JSON file')
    parser.add_argument('--current', required=True, help='Path to current scan JSON file')
    parser.add_argument('--output', default='compliance-diff.html', help='Output HTML file')
    parser.add_argument('--json', action='store_true', help='Also output JSON diff')
    
    args = parser.parse_args()
    
    print(f"📊 Loading baseline: {args.baseline}")
    baseline_data = load_inspec_results(args.baseline)
    baseline_controls = extract_control_statuses(baseline_data)
    
    print(f"📊 Loading current: {args.current}")
    current_data = load_inspec_results(args.current)
    current_controls = extract_control_statuses(current_data)
    
    print("🔍 Comparing controls...")
    regressions, improvements, new_controls, removed_controls = compare_controls(
        baseline_controls, current_controls
    )
    
    stats = calculate_statistics(baseline_controls, current_controls)
    
    # Print summary to console
    print("\n" + "="*60)
    print(f"📈 COMPLIANCE COMPARISON SUMMARY")
    print("="*60)
    print(f"Baseline Score: {stats['baseline']['score']}% ({stats['baseline']['passed']}/{stats['baseline']['total']})")
    print(f"Current Score:  {stats['current']['score']}% ({stats['current']['passed']}/{stats['current']['total']})")
    print(f"Delta:          {'+' if stats['delta']['score'] >= 0 else ''}{stats['delta']['score']}%")
    print("-"*60)
    print(f"🔴 Regressions:   {len(regressions)}")
    print(f"🟢 Improvements:  {len(improvements)}")
    print(f"🆕 New Controls:  {len(new_controls)}")
    print(f"🗑️  Removed:       {len(removed_controls)}")
    print("="*60)
    
    # Generate HTML report
    html = generate_html_report(
        stats, regressions, improvements, new_controls, removed_controls,
        args.baseline, args.current
    )
    
    with open(args.output, 'w') as f:
        f.write(html)
    
    print(f"\n✅ HTML report generated: {args.output}")
    
    # Optionally output JSON
    if args.json:
        json_output = args.output.replace('.html', '.json')
        with open(json_output, 'w') as f:
            json.dump({
                'statistics': stats,
                'regressions': regressions,
                'improvements': improvements,
                'new_controls': new_controls,
                'removed_controls': removed_controls
            }, f, indent=2)
        print(f"✅ JSON diff generated: {json_output}")
    
    # Exit with error code if there are regressions
    if regressions:
        print(f"\n⚠️  WARNING: {len(regressions)} regression(s) detected!")
        exit(1)

if __name__ == '__main__':
    main()
