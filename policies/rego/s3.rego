# OPA/Rego Policy for S3 Bucket Compliance
# Maps to CIS AWS Benchmark 2.1.x controls

package terraform.s3

import future.keywords.in

# Default deny message
default allow = false

# CIS-AWS-2.1.1: Deny S3 buckets that allow HTTP requests
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    bucket := resource.change.after

    # Check if bucket policy or ACL allows public access
    not bucket_has_https_only(bucket)

    msg := sprintf(
        "CIS-AWS-2.1.1 CRITICAL: S3 bucket '%s' must enforce HTTPS-only access. Add bucket policy to deny insecure transport.",
        [resource.address]
    )
}

# CIS-AWS-2.1.2: Deny S3 buckets without encryption
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    bucket := resource.change.after

    not bucket_has_encryption(bucket)

    msg := sprintf(
        "CIS-AWS-2.1.2 CRITICAL: S3 bucket '%s' must have server-side encryption enabled (AES256 or aws:kms).",
        [resource.address]
    )
}

# CIS-AWS-2.1.4: Deny S3 buckets without public access block
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_public_access_block"
    block_config := resource.change.after

    not all_public_access_blocked(block_config)

    msg := sprintf(
        "CIS-AWS-2.1.4 CRITICAL: S3 bucket '%s' must have all public access block settings enabled.",
        [resource.address]
    )
}

# Helper: Check if bucket has HTTPS-only policy
bucket_has_https_only(bucket) {
    bucket.policy != null
    contains(bucket.policy, "aws:SecureTransport")
}

# Helper: Check if bucket has encryption
bucket_has_encryption(bucket) {
    bucket.server_side_encryption_configuration != null
    bucket.server_side_encryption_configuration[_].rule[_].apply_server_side_encryption_by_default.sse_algorithm != null
}

# Helper: Check if all public access is blocked
all_public_access_blocked(block_config) {
    block_config.block_public_acls == true
    block_config.block_public_policy == true
    block_config.ignore_public_acls == true
    block_config.restrict_public_buckets == true
}

# ISO-27017-CLD.10.1.1: Encryption at rest
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    bucket := resource.change.after

    not bucket_has_kms_encryption(bucket)

    msg := sprintf(
        "ISO-27017-CLD.10.1.1 HIGH: S3 bucket '%s' should use KMS encryption for enhanced data protection.",
        [resource.address]
    )
}

# Helper: Check for KMS encryption (higher standard)
bucket_has_kms_encryption(bucket) {
    bucket.server_side_encryption_configuration[_].rule[_].apply_server_side_encryption_by_default.sse_algorithm == "aws:kms"
}

# CIS-AWS-2.1.3: Ensure S3 bucket access logging is enabled
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    bucket := resource.change.after

    not bucket_has_logging(bucket)

    msg := sprintf(
        "CIS-AWS-2.1.3 HIGH: S3 bucket '%s' must have access logging enabled.",
        [resource.address]
    )
}

# Helper: Check if bucket has logging
bucket_has_logging(bucket) {
    bucket.logging != null
    bucket.logging[_].target_bucket != null
}

# PCI-DSS-3.4.1: Render cardholder data unreadable
# Assumes buckets tagged with 'DataClassification=PCI' contain cardholder data
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    bucket := resource.change.after

    bucket.tags.DataClassification == "PCI"
    not bucket_has_kms_encryption(bucket)

    msg := sprintf(
        "PCI-DSS-3.4.1 CRITICAL: S3 bucket '%s' contains PCI data and MUST use KMS encryption.",
        [resource.address]
    )
}

# Best Practice: Versioning should be enabled for data protection
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    bucket := resource.change.after

    not bucket_has_versioning(bucket)

    msg := sprintf(
        "BEST-PRACTICE MEDIUM: S3 bucket '%s' should have versioning enabled for data protection and compliance.",
        [resource.address]
    )
}

# Helper: Check if bucket has versioning
bucket_has_versioning(bucket) {
    bucket.versioning[_].enabled == true
}

# Summary rule for compliance report
compliance_summary[control] {
    control := {
        "standard": "CIS AWS Foundations",
        "controls_checked": ["2.1.1", "2.1.2", "2.1.3", "2.1.4"],
        "iso_controls": ["CLD.10.1.1"],
        "pci_requirements": ["3.4.1"]
    }
}
