# OPA/Rego Policy for Logging Compliance
# Maps to CIS AWS Benchmark 3.x controls

package terraform.logging

import future.keywords.in

# Default deny
default allow = false

# =============================================================================
# CIS 3.1: CloudTrail Enabled in All Regions
# =============================================================================

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudtrail"
    trail := resource.change.after

    not trail.is_multi_region_trail

    msg := sprintf(
        "CIS-AWS-3.1 CRITICAL: CloudTrail '%s' is not multi-region. Enable is_multi_region_trail = true.",
        [resource.address]
    )
}

# =============================================================================
# CIS 3.2: CloudTrail Log File Validation
# =============================================================================

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudtrail"
    trail := resource.change.after

    not trail.enable_log_file_validation

    msg := sprintf(
        "CIS-AWS-3.2 HIGH: CloudTrail '%s' does not have log file validation enabled. Set enable_log_file_validation = true.",
        [resource.address]
    )
}

# =============================================================================
# CIS 3.4: CloudTrail Integration with CloudWatch Logs
# =============================================================================

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudtrail"
    trail := resource.change.after

    not trail.cloud_watch_logs_group_arn

    msg := sprintf(
        "CIS-AWS-3.4 HIGH: CloudTrail '%s' is not integrated with CloudWatch Logs. Set cloud_watch_logs_group_arn.",
        [resource.address]
    )
}

# =============================================================================
# CIS 3.5: AWS Config Enabled
# =============================================================================

# Warn if no AWS Config recorder exists
warn[msg] {
    not config_recorder_exists

    msg := "CIS-AWS-3.5 HIGH: No AWS Config recorder found in configuration. Enable AWS Config in all regions."
}

config_recorder_exists {
    resource := input.resource_changes[_]
    resource.type == "aws_config_configuration_recorder"
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_config_configuration_recorder"
    recorder := resource.change.after

    not recorder.recording_group[_].all_supported

    msg := sprintf(
        "CIS-AWS-3.5 HIGH: AWS Config recorder '%s' is not recording all supported resources.",
        [resource.address]
    )
}

# =============================================================================
# CIS 3.7: CloudTrail KMS Encryption
# =============================================================================

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudtrail"
    trail := resource.change.after

    not trail.kms_key_id

    msg := sprintf(
        "CIS-AWS-3.7 CRITICAL: CloudTrail '%s' logs are not encrypted with KMS CMK. Set kms_key_id.",
        [resource.address]
    )
}

# =============================================================================
# CIS 3.8: KMS Key Rotation
# =============================================================================

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_kms_key"
    key := resource.change.after

    not key.enable_key_rotation

    msg := sprintf(
        "CIS-AWS-3.8 MEDIUM: KMS key '%s' does not have automatic key rotation enabled.",
        [resource.address]
    )
}

# =============================================================================
# CIS 3.9: VPC Flow Logs Enabled
# =============================================================================

# Check if VPC has flow logs
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_vpc"
    vpc := resource.change.after

    not vpc_has_flow_logs(resource.address)

    msg := sprintf(
        "CIS-AWS-3.9 HIGH: VPC '%s' may not have flow logs enabled. Ensure aws_flow_log is configured.",
        [resource.address]
    )
}

vpc_has_flow_logs(vpc_address) {
    resource := input.resource_changes[_]
    resource.type == "aws_flow_log"
    contains(resource.change.after.vpc_id, vpc_address)
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_flow_log"
    flow_log := resource.change.after

    flow_log.traffic_type != "ALL"

    msg := sprintf(
        "CIS-AWS-3.9 MEDIUM: VPC Flow Log '%s' is not capturing ALL traffic. Set traffic_type = 'ALL'.",
        [resource.address]
    )
}

# =============================================================================
# Best Practice: CloudWatch Log Group Retention
# =============================================================================

warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudwatch_log_group"
    log_group := resource.change.after

    not log_group.retention_in_days

    msg := sprintf(
        "BEST-PRACTICE LOW: CloudWatch Log Group '%s' has no retention policy. Set retention_in_days.",
        [resource.address]
    )
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudwatch_log_group"
    log_group := resource.change.after

    log_group.retention_in_days < 90

    msg := sprintf(
        "BEST-PRACTICE MEDIUM: CloudWatch Log Group '%s' retention is less than 90 days. Consider longer retention for compliance.",
        [resource.address]
    )
}

# =============================================================================
# Best Practice: CloudWatch Log Group Encryption
# =============================================================================

warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudwatch_log_group"
    log_group := resource.change.after

    not log_group.kms_key_id

    msg := sprintf(
        "BEST-PRACTICE MEDIUM: CloudWatch Log Group '%s' is not encrypted with KMS.",
        [resource.address]
    )
}

# =============================================================================
# CIS 3.3: CloudTrail S3 Bucket Not Public
# =============================================================================

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_public_access_block"
    block := resource.change.after

    # Check if this is a CloudTrail bucket (by naming convention or tag)
    contains(resource.address, "cloudtrail")

    not block.block_public_acls
    not block.block_public_policy
    not block.ignore_public_acls
    not block.restrict_public_buckets

    msg := sprintf(
        "CIS-AWS-3.3 CRITICAL: CloudTrail S3 bucket '%s' does not have all public access blocks enabled.",
        [resource.address]
    )
}

# =============================================================================
# PCI-DSS 10.2: Audit Trail for All Access
# =============================================================================

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudtrail"
    trail := resource.change.after

    not trail.include_global_service_events

    msg := sprintf(
        "PCI-DSS-10.2 HIGH: CloudTrail '%s' does not include global service events (IAM, STS).",
        [resource.address]
    )
}

# =============================================================================
# S3 Access Logging for CloudTrail Bucket
# =============================================================================

warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    bucket := resource.change.after

    # Check if this is a CloudTrail bucket
    contains(resource.address, "cloudtrail")

    not bucket.logging

    msg := sprintf(
        "CIS-AWS-3.6 MEDIUM: CloudTrail S3 bucket '%s' should have access logging enabled.",
        [resource.address]
    )
}

# =============================================================================
# Compliance Summary
# =============================================================================

compliance_summary[control] {
    control := {
        "standard": "CIS AWS Foundations Benchmark v1.5.0",
        "section": "3. Logging",
        "controls_checked": ["3.1", "3.2", "3.3", "3.4", "3.5", "3.6", "3.7", "3.8", "3.9"],
        "pci_requirements": ["10.2", "10.3", "10.5"]
    }
}
