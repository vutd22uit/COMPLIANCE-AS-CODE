#!/usr/bin/env python3
"""
🚀 SUPER DEMO CONTROL PANEL
---------------------------
A unified interface for the "Compliance-as-Code" Executive Demo.
Allows switching between MOCK (for story-telling) and LIVE (for technical proof).
"""

import os
import sys
import time
import subprocess
from datetime import datetime

# ANSI Colors for Executive Polish
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    clear_screen()
    print(Colors.HEADER + Colors.BOLD + """
    ╔═══════════════════════════════════════════════════════════════╗
    ║      COMPLIANCE-AS-CODE: EXECUTIVE DEMO CONTROL PANEL         ║
    ╚═══════════════════════════════════════════════════════════════╝
    """ + Colors.ENDC)
    print(f"    Current Time: {datetime.now().strftime('%H:%M:%S')}")
    print(f"    User: {os.environ.get('USER', 'admin')}")
    print("-" * 65)

def run_command(command, desc, sleep_time=1):
    print(f"\n{Colors.BLUE}⚡ DOING: {desc}...{Colors.ENDC}")
    time.sleep(0.5)
    try:
        # Run command and capture output
        process = subprocess.Popen(
            command, 
            shell=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Stream output realistically
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                print(f"  {Colors.CYAN}> {output.strip()}{Colors.ENDC}")
                time.sleep(0.05)  # Slight delay for "hacking" effect
        
        if process.returncode == 0:
            print(f"{Colors.GREEN}✅ SUCCESS: {desc} completed.{Colors.ENDC}")
        else:
            print(f"{Colors.FAIL}❌ FAILURE: Command failed.{Colors.ENDC}")
            
    except Exception as e:
        print(f"{Colors.FAIL}❌ ERROR: {e}{Colors.ENDC}")
    
    time.sleep(sleep_time)

def main_menu():
    while True:
        print_banner()
        print(f"{Colors.BOLD}SELECT A DEMO SCENARIO:{Colors.ENDC}\n")
        
        print(f"  {Colors.WARNING}[1] 🔴 MOCK: TRIGGER INCIDENT (Chaos) {Colors.ENDC}")
        print(f"      (Drops compliance score to 45% - Shows Dashboard turning RED)")
        
        print(f"  {Colors.GREEN}[2] 🟢 MOCK: AUTO-FIX (Control) {Colors.ENDC}")
        print(f"      (Restores compliance score to 100% - Shows Dashboard turning GREEN)")
        
        print(f"\n  {Colors.CYAN}[3] 🕵️  LIVE: REAL SCAN (Technical Proof) {Colors.ENDC}")
        print(f"      (Runs actual InSpec against configured OpenStack Host)")
        
        print(f"  {Colors.BLUE}[4] 🛠️  LIVE: REAL REMEDIATION (Dangerous) {Colors.ENDC}")
        print(f"      (Runs Ansible to actually fix config files on target)")
        
        print("\n  [Q] Quit")
        
        choice = input(f"\n{Colors.BOLD}Enter Choice > {Colors.ENDC}").lower()
        
        if choice == '1':
            run_command("python3 scripts/simulate_incident.py --break", "Simulating Critical Security Breach")
            input(f"\n{Colors.WARNING}⚠️  DASHBOARD IS NOW RED. Press Enter to continue...{Colors.ENDC}")
            
        elif choice == '2':
            run_command("python3 scripts/simulate_incident.py --fix", "Executing Automated Remediation Protocols")
            input(f"\n{Colors.GREEN}✅ DASHBOARD IS NOW GREEN. Press Enter to continue...{Colors.ENDC}")
            
        elif choice == '3':
            print(f"\n{Colors.BOLD}Select Scan Target:{Colors.ENDC}")
            print("  [1] Localhost (This machine)")
            print("  [2] Remote SSH (Configured via Env Vars)")
            target = input("  > ")
            
            cmd = "inspec exec tests/inspec/openstack-cis -t local:// --reporter cli"
            if target == '2':
                # Check env vars
                host = os.environ.get('OPENSTACK_HOST')
                user = os.environ.get('OPENSTACK_USER')
                if not host:
                    print(f"{Colors.FAIL}❌ ERROR: OPENSTACK_HOST env var not set!{Colors.ENDC}")
                    time.sleep(2)
                    continue
                cmd = f"inspec exec tests/inspec/openstack-cis -t ssh://{user}@{host} --reporter cli"
                
            run_command(cmd, "Running Live CIS Benchmark Scan")
            input(f"\n{Colors.BLUE}ℹ️  Live scan complete. Press Enter to continue...{Colors.ENDC}")

        elif choice == '4':
            print(f"{Colors.FAIL}{Colors.BOLD}⚠️  WARNING: THIS WILL MODIFY CONFIG FILES!{Colors.ENDC}")
            confirm = input("Type 'yes' to proceed: ")
            if confirm == 'yes':
                run_command("ansible-playbook remediation/ansible/playbooks/site.yml -i 'localhost,' --connection=local", "Applying Ansible Fixes")
            else:
                print("Cancelled.")
            input("Press Enter to continue...")
            
        elif choice == 'q':
            print(f"\n{Colors.CYAN}Goodbye! Good luck with the presentation. 🚀{Colors.ENDC}")
            sys.exit(0)

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)
