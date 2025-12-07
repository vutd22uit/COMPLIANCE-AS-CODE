# OPA/Rego Policy for IAM Compliance
# Maps to CIS AWS Benchmark 1.x controls

package terraform.iam

import future.keywords.in

# Default deny
default allow = false

# =============================================================================
# CIS 1.8: IAM Password Policy - Minimum Length
# =============================================================================

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_account_password_policy"
    policy := resource.change.after

    policy.minimum_password_length < 14

    msg := sprintf(
        "CIS-AWS-1.8 HIGH: IAM password policy '%s' must require minimum password length of 14 or greater. Current: %d",
        [resource.address, policy.minimum_password_length]
    )
}

# =============================================================================
# CIS 1.9: IAM Password Policy - Prevent Reuse
# =============================================================================

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_account_password_policy"
    policy := resource.change.after

    policy.password_reuse_prevention < 24

    msg := sprintf(
        "CIS-AWS-1.9 MEDIUM: IAM password policy '%s' should prevent reuse of last 24 passwords. Current: %d",
        [resource.address, policy.password_reuse_prevention]
    )
}

# =============================================================================
# CIS 1.10: Password Policy - Require Symbols
# =============================================================================

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_account_password_policy"
    policy := resource.change.after

    not policy.require_symbols

    msg := sprintf(
        "CIS-AWS-1.10 MEDIUM: IAM password policy '%s' should require at least one symbol",
        [resource.address]
    )
}

# =============================================================================
# CIS 1.10: Password Policy - Require Numbers
# =============================================================================

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_account_password_policy"
    policy := resource.change.after

    not policy.require_numbers

    msg := sprintf(
        "CIS-AWS-1.10 MEDIUM: IAM password policy '%s' should require at least one number",
        [resource.address]
    )
}

# =============================================================================
# CIS 1.10: Password Policy - Require Uppercase
# =============================================================================

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_account_password_policy"
    policy := resource.change.after

    not policy.require_uppercase_characters

    msg := sprintf(
        "CIS-AWS-1.10 MEDIUM: IAM password policy '%s' should require uppercase characters",
        [resource.address]
    )
}

# =============================================================================
# CIS 1.10: Password Policy - Require Lowercase
# =============================================================================

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_account_password_policy"
    policy := resource.change.after

    not policy.require_lowercase_characters

    msg := sprintf(
        "CIS-AWS-1.10 MEDIUM: IAM password policy '%s' should require lowercase characters",
        [resource.address]
    )
}

# =============================================================================
# CIS 1.16: No Full Admin Privileges
# =============================================================================

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_policy"
    policy := resource.change.after

    has_full_admin_privileges(policy.policy)

    msg := sprintf(
        "CIS-AWS-1.16 CRITICAL: IAM policy '%s' grants full administrative privileges (*:*). This is not allowed.",
        [resource.address]
    )
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_role_policy"
    policy := resource.change.after

    has_full_admin_privileges(policy.policy)

    msg := sprintf(
        "CIS-AWS-1.16 CRITICAL: IAM role inline policy '%s' grants full administrative privileges (*:*)",
        [resource.address]
    )
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_user_policy"
    policy := resource.change.after

    has_full_admin_privileges(policy.policy)

    msg := sprintf(
        "CIS-AWS-1.16 CRITICAL: IAM user inline policy '%s' grants full administrative privileges (*:*). Users should not have direct policies.",
        [resource.address]
    )
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_group_policy"
    policy := resource.change.after

    has_full_admin_privileges(policy.policy)

    msg := sprintf(
        "CIS-AWS-1.16 CRITICAL: IAM group inline policy '%s' grants full administrative privileges (*:*)",
        [resource.address]
    )
}

# Helper: Check for full admin privileges
has_full_admin_privileges(policy_json) {
    policy := json.unmarshal(policy_json)
    statements := get_statements(policy)
    statement := statements[_]
    statement.Effect == "Allow"
    action_is_star(statement.Action)
    resource_is_star(statement.Resource)
}

# Normalize Statement to a list
get_statements(policy) = statements {
    is_array(policy.Statement)
    statements := policy.Statement
}

get_statements(policy) = statements {
    not is_array(policy.Statement)
    statements := [policy.Statement]
}

action_is_star(action) {
    action == "*"
}

action_is_star(action) {
    action[_] == "*"
}

resource_is_star(resource) {
    resource == "*"
}

resource_is_star(resource) {
    resource[_] == "*"
}

# =============================================================================
# CIS 1.15: Users Receive Permissions Through Groups
# =============================================================================

warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_user_policy_attachment"

    msg := sprintf(
        "CIS-AWS-1.15 HIGH: Policy is directly attached to user '%s'. Users should receive permissions through groups only.",
        [resource.address]
    )
}

warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_user_policy"

    msg := sprintf(
        "CIS-AWS-1.15 HIGH: Inline policy attached to user '%s'. Users should receive permissions through groups only.",
        [resource.address]
    )
}

# =============================================================================
# CIS 1.18: Use IAM Roles for EC2 Instances
# =============================================================================

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_instance"
    instance := resource.change.after

    not instance.iam_instance_profile

    msg := sprintf(
        "CIS-AWS-1.18 HIGH: EC2 instance '%s' does not have an IAM instance profile. Use IAM roles for AWS resource access.",
        [resource.address]
    )
}

# =============================================================================
# CIS 1.20: IAM Access Analyzer
# =============================================================================

# Best practice: Ensure Access Analyzer exists
warn[msg] {
    not access_analyzer_exists

    msg := "CIS-AWS-1.20 HIGH: No IAM Access Analyzer found in configuration. Enable Access Analyzer in all regions."
}

access_analyzer_exists {
    resource := input.resource_changes[_]
    resource.type == "aws_accessanalyzer_analyzer"
}

# =============================================================================
# Best Practice: Cross-Account Role Trust
# =============================================================================

warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_role"
    role := resource.change.after

    assume_role_policy := json.unmarshal(role.assume_role_policy)
    statement := assume_role_policy.Statement[_]

    # Check for Principal: "*"
    statement.Principal == "*"

    msg := sprintf(
        "BEST-PRACTICE CRITICAL: IAM role '%s' trusts all AWS principals (Principal: *). This is dangerous.",
        [resource.address]
    )
}

# =============================================================================
# Compliance Summary
# =============================================================================

compliance_summary[control] {
    control := {
        "standard": "CIS AWS Foundations Benchmark v1.5.0",
        "section": "1. Identity and Access Management",
        "controls_checked": ["1.8", "1.9", "1.10", "1.15", "1.16", "1.18", "1.20"]
    }
}
