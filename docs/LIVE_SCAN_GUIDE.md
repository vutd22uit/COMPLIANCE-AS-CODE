# COMPLIANCE-AS-CODE: Live OpenStack Scanning Guide

This guide provides step-by-step instructions for running **Compliance-as-Code** scans against a real OpenStack environment (or a real Linux server) using InSpec and visualizing the results in Grafana.

---

## 📋 Prerequisites

Before you begin, ensure you have the following installed on your machine:

1.  **SysAdmin/DevOps Machine**:
    *   **InSpec**: `curl https://omnitruck.chef.io/install.sh | sudo bash -s -- -P inspec`
    *   **Ansible**: `pipinstall ansible`
    *   **Git**: To clone this repository.
    *   **Podman** (or Docker): To run the monitoring stack.

2.  **Target System (OpenStack Node)**:
    *   SSH Access with `sudo` privileges.
    *   Example: `ubuntu@192.168.1.100`

---

## 🚀 Phase 1: Setup & Configuration

### 1. Clone the Repository
```bash
git clone https://github.com/vutd22uit/COMPLIANCE-AS-CODE.git
cd COMPLIANCE-AS-CODE
```

### 2. Configure Inventory & Credentials
Export the credentials for your target OpenStack node:

```bash
# Target connection details
export OPENSTACK_HOST="192.168.1.100"  # Replace with your real IP
export OPENSTACK_USER="ubuntu"         # Replace with your SSH user
export SSH_KEY_PATH="~/.ssh/id_rsa"    # Path to your private key
```

### 3. Start Monitoring Stack (Grafana/Prometheus)
Launch the dashboard to visualize results in real-time.

```bash
cd dashboards
podman-compose up -d
# Access Grafana at http://localhost:3000 (admin/openstack-cis-2024)
cd ..
```

---

## 🔍 Phase 2: Running Compliance Scans

### A. Run a Scan against a Remote Target (SSH)
This command runs the OpenStack CIS benchmark against your real server using SSH.

```bash
# General Syntax
inspec exec tests/inspec/openstack-cis \
  -t ssh://${OPENSTACK_USER}@${OPENSTACK_HOST} \
  -i ${SSH_KEY_PATH} \
  --reporter cli json:scan-results/real-scan-$(date +%s).json
```

### B. Run a Scan Locally (If running ON the OpenStack node)
If you have InSpec installed directly on the OpenStack controller:

```bash
inspec exec tests/inspec/openstack-cis \
  -t local:// \
  --reporter cli json:scan-results/local-scan-$(date +%s).json
```

> **Note**: The results will be saved to `scan-results/`. The `compliance_exporter` automatically picks up new JSON files in this directory and updates the Grafana dashboard within 30 seconds.

---

## 🛠️ Phase 3: Automated Remediation

If your scan reveals failures (and it likely will!), use Ansible to fix them.

### 1. Verify Connectivity
```bash
ansible all -i "${OPENSTACK_HOST}," -m ping -u ${OPENSTACK_USER} --private-key ${SSH_KEY_PATH}
```

### 2. Run Remediation Playbook (Dry-Run)
Check what *would* be changed without actually modifying anything.

```bash
ansible-playbook remediation/ansible/cis-linux-remediation.yml \
  -i "${OPENSTACK_HOST}," \
  -u ${OPENSTACK_USER} \
  --private-key ${SSH_KEY_PATH} \
  --check --diff
```

### 3. Apply Fixes (Real Remediation)
Apply the security hardening fixes to the target server.

```bash
ansible-playbook remediation/ansible/cis-linux-remediation.yml \
  -i "${OPENSTACK_HOST}," \
  -u ${OPENSTACK_USER} \
  --private-key ${SSH_KEY_PATH} \
  --become
```

---

## 📊 Phase 4: Verification

1.  **Re-Run Scan**: Execute the InSpec scan (Phase 2) again.
2.  **Check Dashboard**: Go to [http://localhost:3000](http://localhost:3000).
    *   The **Compliance Score** should increase (ideally to 100%).
    *   **Remediations Applied** count in the dashboard will increment.
    *   **MTTR** metrics will update.

---

## ⚠️ Troubleshooting

*   **"Authentication Failed"**: Check your SSH key permissions (`chmod 600 ~/.ssh/id_rsa`) and verify the username.
*   **"Sudo password missing"**: If Ansible fails on sudo, add `--ask-become-pass` to the ansible-playbook command to input your sudo password manually.
*   **"No Data in Grafana"**: Ensure the `scan-results/` directory has `.json` files and that the `compliance_exporter` container is running (`podman ps`).

---
**Good Luck with your Live Demo! 🎥**
