# Compliance-as-Code Framework

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

A comprehensive Compliance-as-Code (CaC) framework for automated testing, enforcement, and remediation of security compliance controls across AWS and OpenStack environments.

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

This framework automates compliance checks for:
- **CIS Benchmarks** (AWS Foundations, Linux)
- **ISO 27017** (Cloud-specific controls)
- **PCI-DSS** (Payment card industry data security)

It provides three layers of compliance enforcement:
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

For detailed architecture, see [docs/architecture.md](docs/architecture.md)

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

## Supported Compliance Standards

### CIS Benchmarks
- **CIS AWS Foundations Benchmark v1.5.0**
  - IAM controls
  - Logging & Monitoring
  - Network configuration
  - Storage encryption

- **CIS Linux Benchmark**
  - System hardening
  - Access controls
  - Logging & auditing

### ISO 27017:2015
- Cloud-specific security controls
- Data protection in cloud environments
- Shared responsibility model compliance

### PCI-DSS v4.0
- Cardholder data protection
- Access control requirements
- Logging and monitoring
- Encryption requirements

See [docs/control-mapping.md](docs/control-mapping.md) for complete control coverage.

## Prerequisites

### Required Tools
- **Terraform** >= 1.5.0
- **Python** >= 3.8
- **InSpec** >= 5.0
- **Checkov** >= 2.3
- **OPA** >= 0.50

### Cloud Access
- AWS account with appropriate IAM permissions
- OpenStack environment (optional for full testing)

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
