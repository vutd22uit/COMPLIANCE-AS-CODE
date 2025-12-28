# Compliance-as-Code Framework - OpenStack CIS Benchmark

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)
![OpenStack](https://img.shields.io/badge/OpenStack-Yoga-ED1944?logo=openstack&logoColor=white)
![Kolla](https://img.shields.io/badge/Kolla--Ansible-Yoga-blue)

A comprehensive Compliance-as-Code (CaC) framework for automated testing, enforcement, and remediation of **CIS Benchmark** compliance controls across **OpenStack** cloud infrastructure deployed using **Kolla-Ansible**.

> **🎯 Target Environment**:
> - OpenStack **Yoga** release
> - Deployed via **Kolla-Ansible** on Ubuntu 22.04/24.04
> - CIS OpenStack Foundations Benchmark + CIS Linux Benchmark

---

## 🖥️ Supported Environment

### OpenStack Services (Kolla-Ansible Yoga)

| Service | Component | CIS Coverage |
|---------|-----------|--------------|
| **Keystone** | Identity & Auth | ✅ 6 controls |
| **Nova** | Compute | ✅ 8 controls |
| **Neutron** | Networking (OVS) | ✅ 8 controls |
| **Glance** | Image | ✅ 4 controls |
| **Cinder** | Block Storage | ✅ 4 controls |
| **Swift** | Object Storage | ✅ 4 controls |
| **Horizon** | Dashboard | ✅ 5 controls |
| **Heat** | Orchestration | ✅ 4 controls |
| **HAProxy** | Load Balancer | 🔄 Planned |
| **MariaDB** | Database | 🔄 Planned |
| **RabbitMQ** | Message Queue | 🔄 Planned |

### Linux CIS Benchmark

| Distribution | Version | Coverage |
|--------------|---------|----------|
| Ubuntu | 22.04 / 24.04 | ✅ 45+ controls |
| RHEL/CentOS | 8/9 | 🔄 Planned |

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [CIS Benchmark Coverage](#cis-benchmark-coverage)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Evidence & Reporting](#evidence--reporting)
- [Dashboard](#dashboard)
- [Contributing](#contributing)

---

## Overview

This framework automates **CIS Benchmark compliance checks** specifically for OpenStack environments deployed using Kolla-Ansible. It provides:

### Three-Layer Compliance Enforcement

```
┌─────────────────────────────────────────────────────────────────┐
│  1. PRE-DEPLOYMENT CHECKS (OPA/Rego Policies)                   │
│     - Validate configuration files before deployment            │
│     - Block non-compliant globals.yml settings                  │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  2. RUNTIME SCANNING (InSpec + OpenSCAP)                        │
│     - Scan running containers and host OS                       │
│     - Check /etc/{keystone,nova,neutron,etc.}/*.conf            │
│     - Verify file permissions, TLS settings, auth configs       │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  3. AUTO-REMEDIATION (Ansible Playbooks)                        │
│     - Fix file permissions automatically                        │
│     - Update configuration settings                             │
│     - Restart services via Kolla-Ansible                        │
└─────────────────────────────────────────────────────────────────┘
```

---

## Architecture

### Kolla-Ansible Integration

```
┌─────────────────────────────────────────────────────────────────┐
│                   KOLLA-ANSIBLE DEPLOYMENT                       │
│                   (OpenStack Yoga on Ubuntu)                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │
│  │   Keystone   │  │    Nova      │  │   Neutron    │           │
│  │  Container   │  │  Container   │  │  Container   │           │
│  └──────────────┘  └──────────────┘  └──────────────┘           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │
│  │   Glance     │  │   Horizon    │  │    Heat      │           │
│  │  Container   │  │  Container   │  │  Container   │           │
│  └──────────────┘  └──────────────┘  └──────────────┘           │
│                                                                  │
│  Config Paths:                                                   │
│  └── /etc/kolla/{service}/                                      │
│  └── /var/lib/docker/volumes/kolla_logs/                        │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│               COMPLIANCE-AS-CODE FRAMEWORK                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │   InSpec     │    │  OPA/Rego    │    │   Ansible    │       │
│  │   Scanners   │    │   Policies   │    │  Remediation │       │
│  │  (15 files)  │    │  (5 files)   │    │  (3 files)   │       │
│  └──────────────┘    └──────────────┘    └──────────────┘       │
│          ↓                  ↓                   ↓                │
│  ┌──────────────────────────────────────────────────────┐       │
│  │              EVIDENCE COLLECTION                      │       │
│  │  Collector → Normalizer → Storage → Dashboard        │       │
│  └──────────────────────────────────────────────────────┘       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
COMPLIANCE-AS-CODE/
├── README.md                          # This file
│
├── tests/inspec/
│   ├── openstack-cis/                 # OpenStack CIS controls (11 files)
│   │   ├── os-1-identity*.rb          # Keystone checks
│   │   ├── os-2-compute*.rb           # Nova checks
│   │   ├── os-3-networking*.rb        # Neutron checks
│   │   ├── os-4-storage*.rb           # Cinder/Swift checks
│   │   ├── os-6-image.rb              # Glance checks
│   │   ├── os-7-dashboard.rb          # Horizon checks
│   │   └── os-8-orchestration.rb      # Heat checks
│   └── linux-cis/                     # Linux CIS controls (4 files)
│
├── policies/rego/openstack/           # OPA policies (4 files)
│   ├── keystone.rego                  # Identity policies
│   ├── nova.rego                      # Compute policies
│   ├── neutron.rego                   # Network policies
│   └── storage.rego                   # Storage policies
│
├── remediation/ansible/               # Ansible playbooks (3 files)
│   ├── cis-openstack-remediation.yml  # OpenStack hardening
│   ├── cis-linux-remediation.yml      # Linux hardening
│   └── openstack-hardening.yml        # Additional hardening
│
├── evidence/                          # Evidence collection
│   ├── collectors/evidence_collector.py
│   └── reporters/compliance_reporter.py
│
├── dashboards/                        # Monitoring
│   ├── demo-dashboard.html            # Standalone HTML dashboard
│   ├── grafana/                       # Grafana dashboards
│   ├── prometheus/                    # Prometheus config
│   └── docker-compose.yml             # Monitoring stack
│
├── ci/github-actions/                 # CI/CD
│   └── compliance-check.yml
│
└── docs/                              # Documentation
    ├── architecture.md
    └── getting-started.md
```

---

## CIS Benchmark Coverage

### OpenStack CIS Benchmark (43/50 controls = 86%)

| Section | Controls | Implemented | Config Path |
|---------|----------|-------------|-------------|
| **1. Identity (Keystone)** | 10 | 6 | `/etc/kolla/keystone/` |
| **2. Compute (Nova)** | 12 | 8 | `/etc/kolla/nova/` |
| **3. Networking (Neutron)** | 8 | 8 | `/etc/kolla/neutron/` |
| **4. Storage (Cinder/Swift)** | 6 | 8 | `/etc/kolla/cinder/` |
| **5. Image (Glance)** | 6 | 4 | `/etc/kolla/glance/` |
| **6. Dashboard (Horizon)** | 5 | 5 | `/etc/kolla/horizon/` |
| **7. Orchestration (Heat)** | 3 | 4 | `/etc/kolla/heat/` |

### Linux CIS Benchmark (45+/95 controls = 47%)

| Section | Controls | Implemented |
|---------|----------|-------------|
| 1. Initial Setup | 20 | 15+ |
| 4. Logging & Audit | 22 | 10+ |
| 5. Access & Auth | 15 | 12+ |
| 6. System Maintenance | 10 | 8+ |

---

## Prerequisites

### Required

- **OpenStack Yoga** deployed via Kolla-Ansible
- **Python** >= 3.10
- **InSpec** >= 5.0
- **Ansible** >= 2.12

### OpenStack Access

```bash
# Source your Kolla credentials
source /etc/kolla/admin-openrc.sh

# Verify access
openstack service list
```

---

## Quick Start

### 1. Clone Repository

```bash
git clone https://github.com/vutd22uit/COMPLIANCE-AS-CODE.git
cd COMPLIANCE-AS-CODE
```

### 2. Install Dependencies

```bash
# Install InSpec
curl https://omnitruck.chef.io/install.sh | sudo bash -s -- -P inspec

# Install Python dependencies
pip install -r requirements.txt
```

### 3. Run Compliance Scan

```bash
# Scan OpenStack (from controller node)
inspec exec tests/inspec/openstack-cis \
  -t ssh://deployer@controller-ip \
  --reporter json:scan-results.json \
  --chef-license accept-silent

# Scan using Docker (for containerized services)
for service in keystone nova neutron glance; do
  docker exec kolla_$service cat /etc/$service/$service.conf > /tmp/$service.conf
done

inspec exec tests/inspec/openstack-cis \
  --reporter cli json:results.json
```

### 4. View Dashboard

```bash
# Open demo dashboard
open dashboards/demo-dashboard.html

# Or start full monitoring stack
cd dashboards && docker-compose up -d
# Access Grafana at http://localhost:3000
```

---

## Usage

### Scanning Kolla-Ansible Containers

```bash
# Enter a running container to check configs
docker exec -it keystone bash
cat /etc/keystone/keystone.conf | grep -E "^(admin_token|token_expiration)"

# Or check from host
docker exec keystone cat /etc/keystone/keystone.conf

# Run InSpec against container
inspec exec tests/inspec/openstack-cis/controls/os-1-identity.rb \
  -t docker://keystone
```

### Remediation with Ansible

```bash
# Run OpenStack hardening playbook
ansible-playbook remediation/ansible/cis-openstack-remediation.yml \
  -i /etc/kolla/ansible/inventory/all-in-one \
  --tags keystone,nova

# After remediation, restart services via Kolla
kolla-ansible reconfigure -i /etc/kolla/ansible/inventory/all-in-one
```

---

## Evidence & Reporting

### Collect Evidence

```bash
python evidence/collectors/evidence_collector.py \
  --inspec-json scan-results.json \
  --evidence-path ./evidence_store \
  --store
```

### Generate Report

```bash
python evidence/reporters/compliance_reporter.py \
  --evidence-path ./evidence_store \
  --type daily \
  --format markdown
```

---

## Dashboard

### Demo Dashboard (Standalone HTML)

Open `dashboards/demo-dashboard.html` in any browser for a static compliance view.

### Full Monitoring Stack

```bash
cd dashboards
docker-compose up -d

# Access:
# - Grafana: http://localhost:3000 (admin/openstack-cis-2024)
# - Prometheus: http://localhost:9091
# - Alertmanager: http://localhost:9093
```

---

## 📊 Current Status

```
┌─────────────────────────────────────────────────────────────────┐
│                    PROJECT COMPLETION STATUS                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  OpenStack CIS Benchmark:  ████████████████████░░░░  86%        │
│  Linux CIS Benchmark:      █████████░░░░░░░░░░░░░░░  47%        │
│  Evidence System:          ████████████████████████  100%       │
│  Dashboard:                ████████████████████████  100%       │
│  CI/CD Integration:        ████████████████████████  100%       │
│                                                                  │
│  Total Files: 55 | Controls: 88+ | Ready for Production: YES   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature/new-control`
3. Commit changes: `git commit -m 'Add new control'`
4. Push: `git push origin feature/new-control`
5. Create Pull Request

---

## References

- [CIS OpenStack Benchmark](https://www.cisecurity.org/benchmark/openstack)
- [CIS Ubuntu Linux Benchmark](https://www.cisecurity.org/benchmark/ubuntu_linux)
- [Kolla-Ansible Documentation](https://docs.openstack.org/kolla-ansible/yoga/)
- [OpenStack Security Guide](https://docs.openstack.org/security-guide/)
- [InSpec Documentation](https://docs.chef.io/inspec/)

---

## License

MIT License - See [LICENSE](LICENSE)

---

**Last Updated**: 2025-12-29
**OpenStack Version**: Yoga (Kolla-Ansible)
**Author**: Capstone Project Team
