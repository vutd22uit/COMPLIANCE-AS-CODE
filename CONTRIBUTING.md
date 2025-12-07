# Contributing to Compliance-as-Code Framework

Thank you for your interest in contributing to the Compliance-as-Code Framework! This document provides guidelines and instructions for contributing.

## Table of Contents
- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Adding New Controls](#adding-new-controls)
- [Writing Policies](#writing-policies)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)

## Code of Conduct

- Be respectful and professional
- Focus on constructive feedback
- Prioritize security and compliance
- Document your changes

## How to Contribute

### Types of Contributions

1. **New Compliance Controls**: Add support for new CIS, ISO, or PCI controls
2. **Bug Fixes**: Fix issues in existing policies or checks
3. **Documentation**: Improve guides, examples, or API docs
4. **Testing**: Add unit tests, integration tests, or improve coverage
5. **Tooling**: Enhance CI/CD pipelines or development tools

## Development Setup

### 1. Fork and Clone

```bash
git fork https://github.com/yourorg/COMPLIANCE-AS-CODE.git
git clone https://github.com/yourusername/COMPLIANCE-AS-CODE.git
cd COMPLIANCE-AS-CODE
```

### 2. Install Dependencies

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Install pre-commit hooks
pre-commit install

# Install InSpec
curl https://omnitruck.chef.io/install.sh | sudo bash -s -- -P inspec

# Install Checkov
pip install checkov
```

### 3. Create a Branch

```bash
git checkout -b feature/add-cis-control-xyz
```

## Adding New Controls

### Step 1: Create Control Definition

Create a YAML file in `config/controls/`:

```bash
cp config/controls/control-template.yml config/controls/CIS-AWS-X.X.yml
```

Fill in all required fields:
- Control ID, title, description
- Severity level
- IaC and runtime checks
- Enforcement and remediation

### Step 2: Implement IaC Checks

#### Option A: Rego Policy (OPA)

Create a new Rego file in `policies/rego/`:

```rego
package terraform.example

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_example"
  # Your policy logic here
  msg := sprintf("Control CIS-AWS-X.X violation: %s", [resource.address])
}
```

#### Option B: Checkov Custom Policy

If the control isn't covered by built-in Checkov checks, create a custom policy:

```python
# policies/checkov/custom_checks/example.py
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

class ExampleCheck(BaseResourceCheck):
    def __init__(self):
        name = "Ensure example resource is compliant"
        id = "CKV_AWS_CUSTOM_1"
        supported_resources = ['aws_example']
        categories = ['GENERAL_SECURITY']
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        # Your check logic here
        return CheckResult.PASSED
```

### Step 3: Implement Runtime Checks

#### InSpec Control

Create or update an InSpec control in `tests/inspec/aws-cis/controls/`:

```ruby
control 'cis-aws-x-x' do
  impact 1.0
  title 'Control Title'
  desc 'Control Description'

  tag cis: 'CIS-AWS-X.X'
  tag severity: 'critical'

  # Your InSpec test code
  describe aws_resource('resource_name') do
    it { should meet_requirement }
  end
end
```

### Step 4: Implement Remediation

#### Cloud Custodian Policy

Add to `policies/custodian/`:

```yaml
policies:
  - name: remediate-control-xyz
    resource: aws.service
    filters:
      - type: value
        key: property
        value: non_compliant_value
    actions:
      - type: remediation_action
        # Action parameters
```

#### Ansible Playbook

Create in `remediation/ansible/`:

```yaml
---
- name: Remediate CIS-AWS-X.X
  hosts: localhost
  tasks:
    - name: Fix the issue
      # Ansible tasks
```

### Step 5: Add Tests

```bash
# Unit tests
tests/unit/test_control_xyz.py

# Integration tests
tests/integration/test_control_xyz_remediation.py
```

### Step 6: Update Documentation

1. Add control to `docs/control-mapping.md`
2. Update coverage statistics
3. Add examples if needed

## Writing Policies

### Rego Policy Guidelines

1. **Organize by service**: One file per AWS service (e.g., `s3.rego`, `iam.rego`)
2. **Use clear package names**: `package terraform.service_name`
3. **Provide helpful messages**: Include control ID and clear violation description
4. **Add comments**: Explain complex logic
5. **Test thoroughly**: Include unit tests

Example structure:

```rego
package terraform.s3

# CIS-AWS-2.1.X: Control description
deny[msg] {
    # Condition checks
    msg := sprintf("CIS-AWS-2.1.X CRITICAL: %s", [description])
}

# Helper functions
helper_function(resource) {
    # Logic
}
```

### InSpec Control Guidelines

1. **One file per section**: Group related controls
2. **Use descriptive control IDs**: Match CIS control numbers
3. **Add metadata tags**: Include CIS ID, severity, standard
4. **Provide clear descriptions**
5. **Handle edge cases**: Check for resource existence

## Testing

### Run All Tests

```bash
# Pre-commit checks
pre-commit run --all-files

# Unit tests
pytest tests/unit/

# Integration tests
pytest tests/integration/

# IaC scans
checkov -d examples/terraform/

# Rego policy tests
opa test policies/rego/ -v
```

### Test Your Control

```bash
# Test IaC check
cd examples/terraform/
terraform init
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > tfplan.json
conftest test tfplan.json -p ../../policies/rego/

# Test InSpec control
inspec exec tests/inspec/aws-cis --controls cis-aws-x-x -t aws://

# Test remediation
custodian run -s output policies/custodian/your-policy.yml --dryrun
```

## Pull Request Process

### Before Submitting

1. **Run all tests**: Ensure tests pass
2. **Update documentation**: Document new features
3. **Follow conventions**: Use consistent naming and structure
4. **Add examples**: Provide usage examples
5. **Update CHANGELOG**: Document your changes

### PR Checklist

- [ ] Code follows project style guidelines
- [ ] Pre-commit hooks pass
- [ ] All tests pass
- [ ] Documentation updated
- [ ] Control mapping updated
- [ ] Examples provided
- [ ] CHANGELOG updated
- [ ] Commits are signed

### Submit PR

```bash
git add .
git commit -s -m "feat: Add CIS-AWS-X.X control for [description]"
git push origin feature/add-cis-control-xyz
```

Create a PR on GitHub with:
- Clear title: `feat: Add CIS-AWS-X.X - Control Description`
- Description of changes
- Link to related issues
- Screenshots (if UI changes)
- Testing evidence

### PR Review Process

1. **Automated checks**: CI/CD pipeline runs all checks
2. **Security review**: Security team reviews compliance logic
3. **Code review**: At least one maintainer approval required
4. **Testing**: Manual testing if needed
5. **Merge**: Squash and merge to main

## Coding Standards

### Python

- Follow PEP 8
- Use Black for formatting
- Add type hints
- Write docstrings
- Maximum line length: 100

### Terraform

- Use `terraform fmt`
- Add comments for complex logic
- Use variables for configurability
- Tag all resources

### Rego

- Use descriptive variable names
- Add comments for business logic
- Group related rules
- Use helper functions

### YAML

- 2-space indentation
- Use quotes for strings
- Validate with yamllint

## Commit Message Guidelines

Follow Conventional Commits:

- `feat:` New feature or control
- `fix:` Bug fix
- `docs:` Documentation changes
- `test:` Adding tests
- `refactor:` Code refactoring
- `chore:` Maintenance tasks

Examples:
```
feat: Add CIS-AWS-2.1.5 S3 encryption control
fix: Correct InSpec control for root user MFA
docs: Update getting started guide
test: Add unit tests for S3 Rego policies
```

## Questions?

- Open an issue for questions
- Join our Slack: #compliance-as-code
- Email: cloud-security@company.com

## License

By contributing, you agree that your contributions will be licensed under the same license as the project (Apache 2.0).

---

Thank you for contributing to making cloud infrastructure more secure! 🔒
