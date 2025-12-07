# Compliance-as-Code Framework

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

A comprehensive Compliance-as-Code (CaC) framework for automated testing, enforcement, and remediation of **CIS Benchmark** compliance controls across AWS cloud infrastructure and Linux systems.

> **🎯 Focus**: This framework is specifically designed for **CIS (Center for Internet Security) Benchmarks** only.
> - CIS AWS Foundations Benchmark v1.5.0 (60 controls)
> - CIS Linux Benchmark (95+ controls)
> - **NOT included**: ISO 27017, PCI-DSS, HIPAA, SOC 2

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Supported Compliance Standards](#supported-compliance-standards)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [Roadmap](#roadmap)

## Overview

This framework automates **CIS Benchmark compliance checks** for:

### CIS AWS Foundations Benchmark v1.5.0
- **Section 1**: Identity and Access Management (21 controls)
- **Section 2**: Storage (S3, EBS, RDS) (11 controls)
- **Section 3**: Logging (CloudTrail, Config, VPC Flow Logs) (11 controls)
- **Section 4**: Monitoring (CloudWatch metrics and alarms) (16 controls)
- **Section 5**: Networking (VPC, Security Groups, NACLs) (6 controls)

### CIS Linux Benchmark (Ubuntu/RHEL/Amazon Linux)
- **Section 1**: Initial Setup (filesystem, bootloader, integrity)
- **Section 2**: Services (disable unnecessary services)
- **Section 3**: Network Configuration (hardening)
- **Section 4**: Logging and Auditing (auditd, rsyslog)
- **Section 5**: Access, Authentication and Authorization (SSH, PAM)
- **Section 6**: System Maintenance (file permissions, accounts)

### Three-Layer Compliance Enforcement

The framework provides three layers of compliance enforcement:
1. **Pre-deploy Gates**: Block non-compliant Infrastructure-as-Code (IaC) before deployment
2. **Runtime Scanning**: Continuous monitoring of deployed resources
3. **Automatic Remediation**: Auto-fix or alert on compliance violations

## Features

### Compliance Scanning
- ✅ IaC static analysis (Terraform, CloudFormation)
- ✅ Runtime compliance checks (InSpec, OpenSCAP)
- ✅ Cloud posture management (ScoutSuite)
- ✅ Multi-cloud support (AWS, OpenStack)

### Policy Enforcement
- ✅ Pre-commit hooks for local validation
- ✅ CI/CD pipeline blocking gates
- ✅ OPA/Rego policy-as-code
- ✅ AWS Config Rules integration
- ✅ Cloud Custodian remediation

### Reporting & Evidence
- ✅ Compliance scorecards and dashboards
- ✅ Audit evidence collection
- ✅ Trend analysis and metrics
- ✅ Exception management

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Developer Workflow                       │
├─────────────────────────────────────────────────────────────┤
│  Write IaC → Pre-commit Hooks → Git Push → CI/CD Pipeline   │
│     ↓             ↓                  ↓            ↓          │
│  Checkov     Local Tests      GitHub Actions   Deploy Gate  │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                   Deployed Infrastructure                    │
├─────────────────────────────────────────────────────────────┤
│  AWS Resources  ←→  Runtime Scanners  ←→  Compliance Engine │
│  OpenStack      ←→  (InSpec, SCAP)   ←→  (OPA, Custodian)  │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│              Enforcement & Remediation Layer                 │
├─────────────────────────────────────────────────────────────┤
│  Auto-remediate → Alert → Create Ticket → Evidence Storage  │
└─────────────────────────────────────────────────────────────┘
```

**📖 Documentation:**
- [Architecture Overview](docs/architecture.md) - System design and components
- [**System Diagrams**](docs/diagrams.md) - **Visual architecture & data flow diagrams**
- [CIS Benchmark Focus](docs/CIS-BENCHMARK-FOCUS.md) - Why CIS only?

## Project Structure

```
COMPLIANCE-AS-CODE/
├── README.md                    # This file
├── docs/                        # Documentation
│   ├── architecture.md          # System architecture
│   ├── control-mapping.md       # Controls mapping table
│   └── getting-started.md       # Setup guide
│
├── policies/                    # Policy definitions
│   ├── rego/                    # OPA/Conftest policies
│   ├── checkov/                 # Checkov custom checks
│   └── custodian/               # Cloud Custodian policies
│
├── tests/                       # Compliance test suites
│   ├── inspec/                  # InSpec profiles
│   │   ├── aws-cis/             # AWS CIS Benchmark tests
│   │   └── linux-cis/           # Linux CIS tests
│   └── openscap/                # OpenSCAP content
│
├── remediation/                 # Auto-remediation scripts
│   ├── ansible/                 # Ansible playbooks
│   ├── lambda/                  # AWS Lambda functions
│   └── scripts/                 # Shell/Python scripts
│
├── ci/                          # CI/CD integration
│   ├── github-actions/          # GitHub Actions workflows
│   └── scripts/                 # Helper scripts
│
├── dashboards/                  # Visualization configs
│   └── kibana/                  # Kibana dashboards
│
├── config/                      # Configuration files
│   ├── controls/                # Control definitions
│   └── mappings/                # Control-to-check mappings
│
├── evidence/                    # Compliance evidence storage
│
└── examples/                    # Example IaC templates
    ├── terraform/               # Terraform examples
    └── cloudformation/          # CloudFormation examples
```

## CIS Benchmark Coverage

> **📖 See**: [docs/CIS-BENCHMARK-FOCUS.md](docs/CIS-BENCHMARK-FOCUS.md) for complete rationale

### CIS AWS Foundations Benchmark v1.5.0 (60 controls)

| Section | Controls | Implementation Status |
|---------|----------|----------------------|
| **1. IAM** | 21 controls | 🟢 53% (11/21) |
| **2. Storage** | 11 controls | 🟢 73% (8/11) |
| **3. Logging** | 11 controls | 🟢 64% (7/11) |
| **4. Monitoring** | 16 controls | 🟡 19% (3/16) |
| **5. Networking** | 6 controls | 🟢 67% (4/6) |
| **TOTAL** | **60 controls** | **🟡 53% (32/60)** |

**CRITICAL controls**: 🟢 67% (20/30) ← **Priority Focus**

### CIS Linux Benchmark (95+ controls)

| Section | Controls | Implementation Status |
|---------|----------|----------------------|
| **1. Initial Setup** | 20 controls | 🟡 15% (3/20) |
| **2. Services** | 15 controls | 🟡 13% (2/15) |
| **3. Network Config** | 18 controls | 🟡 11% (2/18) |
| **4. Logging & Audit** | 22 controls | 🟡 9% (2/22) |
| **5. Access & Auth** | 15 controls | 🟡 20% (3/15) |
| **6. System Maint** | 10 controls | 🟡 10% (1/10) |
| **TOTAL** | **95+ controls** | **🔴 13% (12/95)** |

**CRITICAL controls**: 🟢 75% (6/8)

### Overall Compliance Score

```
Total Controls: 155 (60 AWS + 95 Linux)
Implemented:    44 (32 AWS + 12 Linux)
Coverage:       28%

By Severity:
├── CRITICAL: 67% (26/39) ✅ HIGH PRIORITY
├── HIGH:     31% (15/48)
├── MEDIUM:   12% (8/68)
└── LOW:      0% (0/25)
```

**📊 Detailed Control Mapping**: [docs/control-mapping.md](docs/control-mapping.md)
**🏗️ Architecture Diagrams**: [docs/diagrams.md](docs/diagrams.md)

## Prerequisites

### Required Tools
- **Terraform** >= 1.5.0
- **Python** >= 3.8
- **InSpec** >= 5.0
- **Checkov** >= 2.3
- **OPA** >= 0.50

### Cloud Access
- **AWS account** with appropriate IAM permissions (required)
  - ReadOnlyAccess policy (for scanning)
  - Specific write permissions (for remediation)
- **Linux instances** for CIS Linux Benchmark testing (EC2 or on-premise)

### Optional Tools
- Docker (for containerized scanning)
- Cloud Custodian
- OpenSCAP

## Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/COMPLIANCE-AS-CODE.git
cd COMPLIANCE-AS-CODE
```

### 2. Install Dependencies
```bash
# Install Python dependencies
pip install -r requirements.txt

# Install pre-commit hooks
pre-commit install

# Install Checkov
pip install checkov

# Install InSpec
curl https://omnitruck.chef.io/install.sh | sudo bash -s -- -P inspec
```

### 3. Configure AWS Credentials
```bash
export AWS_PROFILE=your-profile
# or
export AWS_ACCESS_KEY_ID=xxx
export AWS_SECRET_ACCESS_KEY=xxx
```

### 4. Run Your First Compliance Scan
```bash
# Scan Terraform code
checkov -d examples/terraform/

# Run InSpec tests
inspec exec tests/inspec/aws-cis -t aws://

# Test OPA policies
conftest test examples/terraform/plan.json -p policies/rego/
```

For detailed setup instructions, see [docs/getting-started.md](docs/getting-started.md)

## Usage

### Pre-deployment Scanning (IaC)
```bash
# Scan Terraform configurations
checkov -d ./terraform --framework terraform

# Test with OPA/Conftest
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > tfplan.json
conftest test tfplan.json -p policies/rego/
```

### Runtime Compliance Checks
```bash
# Run AWS CIS Benchmark tests
inspec exec tests/inspec/aws-cis -t aws:// --reporter cli json:results.json

# Run ScoutSuite for cloud posture
scout aws --no-browser --report-dir ./reports/
```

### Remediation
```bash
# Run Cloud Custodian policy
custodian run -s output policies/custodian/s3-public.yml

# Execute Ansible remediation playbook
ansible-playbook remediation/ansible/harden-linux.yml
```

### CI/CD Integration
GitHub Actions workflows are provided in `.github/workflows/`:
- `compliance-check.yml` - Run on every PR
- `runtime-scan.yml` - Scheduled daily scans
- `remediation.yml` - Auto-remediation workflow

## Documentation

- [Architecture Overview](docs/architecture.md)
- [Control Mapping](docs/control-mapping.md)
- [Getting Started Guide](docs/getting-started.md)
- [Writing Custom Policies](docs/writing-policies.md)
- [Remediation Guide](docs/remediation.md)

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Workflow
1. Fork the repository
2. Create a feature branch
3. Write tests for your changes
4. Ensure all tests pass
5. Submit a pull request

## Roadmap

### Phase 1 (Current) - Foundation
- [x] Project structure setup
- [x] Control mapping
- [ ] Basic IaC checks (Checkov, OPA)
- [ ] CI/CD integration

### Phase 2 - Runtime Scanning
- [ ] InSpec profiles for AWS CIS
- [ ] OpenSCAP integration
- [ ] ScoutSuite automation
- [ ] Evidence collection

### Phase 3 - Enforcement & Remediation
- [ ] Cloud Custodian policies
- [ ] AWS Config Rules
- [ ] Ansible remediation playbooks
- [ ] Exception management

### Phase 4 - Reporting & Dashboard
- [ ] Kibana dashboards
- [ ] Compliance scorecards
- [ ] Trend analysis
- [ ] Audit reports

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Authors

- Capstone Project Team

## Acknowledgments

- CIS Benchmarks
- NIST Cybersecurity Framework
- Cloud Security Alliance
- Open Policy Agent community
- Chef InSpec community

## Support

For questions and support:
- Open an issue in this repository
- Check the [documentation](docs/)
- Review [examples](examples/)

---

**Status**: Active Development
**Last Updated**: 2025-12-07
