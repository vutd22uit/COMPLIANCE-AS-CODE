# Getting Started with Compliance-as-Code Framework

This guide will help you set up and start using the Compliance-as-Code framework.

## Table of Contents
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Initial Configuration](#initial-configuration)
- [Running Your First Scan](#running-your-first-scan)
- [Understanding Results](#understanding-results)
- [Next Steps](#next-steps)

---

## Prerequisites

### Required Software

| Tool | Minimum Version | Purpose | Installation |
|------|----------------|---------|--------------|
| **Terraform** | 1.5.0+ | Infrastructure as Code | [Download](https://www.terraform.io/downloads) |
| **Python** | 3.8+ | Scripting and tools | [Download](https://www.python.org/downloads/) |
| **Git** | 2.30+ | Version control | [Download](https://git-scm.com/downloads) |
| **InSpec** | 5.0+ | Compliance testing | See below |
| **Docker** | 20.0+ (optional) | Containerized scanning | [Download](https://docs.docker.com/get-docker/) |

### Cloud Access

#### AWS
- Active AWS account
- IAM user with permissions for:
  - ReadOnlyAccess (for scanning)
  - Specific write permissions (for remediation)
- AWS CLI configured

#### OpenStack (Optional)
- OpenStack environment access
- Credentials file (`clouds.yaml`)

### Recommended Tools
- VS Code with Terraform extension
- jq (for JSON parsing)
- yq (for YAML parsing)

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/COMPLIANCE-AS-CODE.git
cd COMPLIANCE-AS-CODE
```

### 2. Install Python Dependencies

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

Create `requirements.txt`:
```txt
checkov>=2.3.0
boto3>=1.26.0
ansible>=2.14.0
pyyaml>=6.0
jinja2>=3.1.0
pytest>=7.2.0
```

### 3. Install InSpec

```bash
# Using Chef's installer script
curl https://omnitruck.chef.io/install.sh | sudo bash -s -- -P inspec

# Verify installation
inspec --version
```

### 4. Install Checkov

```bash
pip install checkov

# Verify installation
checkov --version
```

### 5. Install OPA and Conftest

```bash
# Install OPA
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
chmod +x opa
sudo mv opa /usr/local/bin/

# Install Conftest
wget https://github.com/open-policy-agent/conftest/releases/download/v0.45.0/conftest_0.45.0_Linux_x86_64.tar.gz
tar xzf conftest_0.45.0_Linux_x86_64.tar.gz
sudo mv conftest /usr/local/bin/

# Verify
opa version
conftest --version
```

### 6. Install Cloud Custodian (Optional)

```bash
pip install c7n c7n-org

# Verify
custodian version
```

### 7. Install Pre-commit Hooks

```bash
pip install pre-commit

# Install hooks
pre-commit install

# Test hooks
pre-commit run --all-files
```

---

## Initial Configuration

### 1. Configure AWS Credentials

```bash
# Option A: Using AWS CLI
aws configure
# Enter your access key, secret key, region, and output format

# Option B: Using environment variables
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-east-1

# Option C: Using AWS profiles (recommended)
# Edit ~/.aws/credentials
[compliance-scanner]
aws_access_key_id = your_access_key
aws_secret_access_key = your_secret_key

# Edit ~/.aws/config
[profile compliance-scanner]
region = us-east-1
output = json
```

### 2. Configure InSpec AWS Profile

```bash
# Create InSpec input file
mkdir -p ~/.inspec
cat > ~/.inspec/inputs-aws.yml <<EOF
aws_region: us-east-1
aws_profile: compliance-scanner
EOF
```

### 3. Set Up Environment Variables

```bash
# Create .env file (DO NOT commit this)
cat > .env <<EOF
# AWS Configuration
export AWS_PROFILE=compliance-scanner
export AWS_REGION=us-east-1

# Scanning Configuration
export SCAN_RESULTS_BUCKET=my-compliance-evidence-bucket
export EVIDENCE_RETENTION_DAYS=2555  # 7 years

# Notification Configuration
export SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK
export ALERT_EMAIL=security@yourcompany.com

# Compliance Standards
export ENABLED_STANDARDS=cis-aws,iso-27017,pci-dss
EOF

# Load environment
source .env
```

### 4. Create S3 Evidence Bucket

```bash
# Create bucket for storing compliance evidence
aws s3 mb s3://my-compliance-evidence-bucket-$(date +%s) --region us-east-1

# Enable versioning
aws s3api put-bucket-versioning \
  --bucket my-compliance-evidence-bucket \
  --versioning-configuration Status=Enabled

# Block public access
aws s3api put-public-access-block \
  --bucket my-compliance-evidence-bucket \
  --public-access-block-configuration \
    BlockPublicAcls=true,\
    IgnorePublicAcls=true,\
    BlockPublicPolicy=true,\
    RestrictPublicBuckets=true
```

### 5. Configure Pre-commit Hooks

Create `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/antonbabenko/pre-commit-terraform
    rev: v1.83.5
    hooks:
      - id: terraform_fmt
      - id: terraform_validate
      - id: terraform_tfsec
        args:
          - --args=--minimum-severity=HIGH

  - repo: https://github.com/bridgecrewio/checkov
    rev: 2.5.0
    hooks:
      - id: checkov
        args:
          - --framework=terraform
          - --skip-check=CKV_AWS_144  # Example: skip specific check

  - repo: https://github.com/instrumenta/conftest
    rev: v0.45.0
    hooks:
      - id: conftest
        files: \.tf$
        args:
          - test
          - --policy=policies/rego
```

---

## Running Your First Scan

### 1. Scan Terraform Code (IaC)

#### Using Checkov

```bash
# Scan entire directory
checkov -d examples/terraform/

# Scan with specific framework
checkov -d examples/terraform/ --framework terraform

# Output to JSON
checkov -d examples/terraform/ --output json > checkov-results.json

# Scan with severity threshold
checkov -d examples/terraform/ --compact --quiet \
  --hard-fail-on CRITICAL,HIGH
```

#### Using tfsec

```bash
cd examples/terraform/
tfsec .
```

#### Using Conftest (OPA)

```bash
# Generate Terraform plan
cd examples/terraform/
terraform init
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > tfplan.json

# Test with Conftest
conftest test tfplan.json -p ../../policies/rego/

# Test with specific policy
conftest test tfplan.json \
  -p ../../policies/rego/s3.rego \
  --output table
```

### 2. Scan AWS Runtime Environment

#### Using InSpec

```bash
# Run AWS CIS Benchmark profile
inspec exec tests/inspec/aws-cis \
  -t aws:// \
  --input-file ~/.inspec/inputs-aws.yml \
  --reporter cli json:aws-cis-results.json

# Run specific control
inspec exec tests/inspec/aws-cis \
  -t aws:// \
  --controls cis-aws-1-4

# Run with detailed output
inspec exec tests/inspec/aws-cis \
  -t aws:// \
  --reporter cli:- json:results.json html:report.html
```

#### Using ScoutSuite

```bash
# Install ScoutSuite
pip install scoutsuite

# Run AWS scan
scout aws --profile compliance-scanner --no-browser

# View report
open scoutsuite-report/scoutsuite_results_aws-*.html
```

### 3. Scan Linux Instances

#### Using InSpec

```bash
# SSH to instance
inspec exec tests/inspec/linux-cis \
  -t ssh://user@hostname \
  --key-files ~/.ssh/id_rsa \
  --reporter json:linux-cis-results.json

# Multiple instances
for host in $(cat hosts.txt); do
  inspec exec tests/inspec/linux-cis -t ssh://ec2-user@$host
done
```

#### Using OpenSCAP

```bash
# On the target Linux instance
sudo oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis \
  --results results.xml \
  --report report.html \
  /usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml
```

---

## Understanding Results

### Checkov Output

```
Check: CKV_AWS_18: "Ensure S3 bucket has access logging enabled"
PASSED for resource: aws_s3_bucket.compliant_bucket
File: /main.tf:10-15

Check: CKV_AWS_19: "Ensure S3 bucket is encrypted"
FAILED for resource: aws_s3_bucket.non_compliant_bucket
File: /main.tf:20-25
Guide: https://docs.bridgecrew.io/docs/s3_14-data-encrypted-at-rest
```

**Key Fields:**
- **Check ID**: `CKV_AWS_18`
- **Status**: PASSED, FAILED, SKIPPED
- **Resource**: Specific Terraform resource
- **File & Line**: Where the issue is

### InSpec Output

```json
{
  "controls": [
    {
      "id": "cis-aws-1-4",
      "title": "Ensure no root account access key exists",
      "status": "failed",
      "results": [
        {
          "status": "failed",
          "code_desc": "AWS IAM Root User should not have access key",
          "message": "expected AWS IAM Root User not to have access key"
        }
      ]
    }
  ]
}
```

**Key Fields:**
- **Control ID**: Maps to CIS control
- **Status**: passed, failed, skipped
- **Results**: Detailed test results

### Severity Levels

| Level | Description | Action Required |
|-------|-------------|-----------------|
| **CRITICAL** | Immediate security risk | Block deployment, alert immediately |
| **HIGH** | Significant security gap | Block or require approval |
| **MEDIUM** | Security improvement needed | Create ticket, remediate soon |
| **LOW** | Best practice violation | Advisory only |

---

## Next Steps

### 1. Set Up CI/CD Integration

See `.github/workflows/compliance-check.yml` for GitHub Actions example.

```bash
# Copy workflow template
mkdir -p .github/workflows
cp ci/github-actions/compliance-check.yml .github/workflows/
```

### 2. Create Your First Policy

```bash
# Create Rego policy
cat > policies/rego/my-policy.rego <<EOF
package terraform.my_policy

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_instance"
  not resource.change.after.monitoring
  msg = sprintf("EC2 instance %s must have detailed monitoring enabled", [resource.address])
}
EOF

# Test it
conftest test examples/terraform/plan.json -p policies/rego/my-policy.rego
```

### 3. Create Your First InSpec Control

```bash
# Create custom profile
inspec init profile --platform aws my-custom-checks

# Edit controls
cat > my-custom-checks/controls/example.rb <<EOF
control 'my-company-1' do
  impact 1.0
  title 'All S3 buckets must be tagged with Owner'

  aws_s3_buckets.bucket_names.each do |bucket_name|
    describe aws_s3_bucket(bucket_name: bucket_name) do
      its('tags') { should include 'Owner' }
    end
  end
end
EOF

# Run it
inspec exec my-custom-checks -t aws://
```

### 4. Set Up Automated Remediation

```bash
# Create Cloud Custodian policy
cat > policies/custodian/s3-encryption.yml <<EOF
policies:
  - name: s3-enable-encryption
    resource: aws.s3
    filters:
      - type: value
        key: ServerSideEncryptionConfiguration
        value: absent
    actions:
      - type: set-encryption
        algorithm: AES256
EOF

# Test it (dry-run)
custodian run -s output policies/custodian/s3-encryption.yml --dryrun
```

### 5. Explore the Documentation

- [Architecture](architecture.md) - Understand the system design
- [Control Mapping](control-mapping.md) - See all compliance controls
- [Writing Policies](writing-policies.md) - Create custom policies
- [Remediation Guide](remediation.md) - Set up auto-remediation

---

## Troubleshooting

### Common Issues

#### Issue: "InSpec cannot connect to AWS"

**Solution:**
```bash
# Verify AWS credentials
aws sts get-caller-identity

# Check InSpec can access AWS
inspec detect -t aws://
```

#### Issue: "Checkov fails with module not found"

**Solution:**
```bash
# Reinstall in virtual environment
deactivate
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install checkov
```

#### Issue: "Terraform plan fails in Conftest"

**Solution:**
```bash
# Ensure plan is in JSON format
terraform show -json tfplan.binary | jq . > tfplan.json

# Verify JSON is valid
jq empty tfplan.json
```

#### Issue: "Permission denied errors when scanning AWS"

**Solution:**
```bash
# Verify IAM permissions
aws iam get-user

# Attach ReadOnlyAccess policy (for scanning)
aws iam attach-user-policy \
  --user-name scanner-user \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
```

---

## Additional Resources

### Official Documentation
- [Checkov Docs](https://www.checkov.io/documentation.html)
- [InSpec Docs](https://docs.chef.io/inspec/)
- [OPA Docs](https://www.openpolicyagent.org/docs/latest/)
- [Cloud Custodian Docs](https://cloudcustodian.io/docs/)

### CIS Benchmarks
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- [CIS Linux Benchmarks](https://www.cisecurity.org/cis-benchmarks/#linux)

### Community
- [Checkov GitHub](https://github.com/bridgecrewio/checkov)
- [InSpec GitHub](https://github.com/inspec/inspec)
- [OPA Slack](https://slack.openpolicyagent.org/)

---

## Getting Help

- **Issues**: Open an issue in this repository
- **Questions**: Check the [FAQ](FAQ.md)
- **Security**: Email security@yourcompany.com

---

**Last Updated**: 2025-12-07
**Maintained By**: Platform Team
