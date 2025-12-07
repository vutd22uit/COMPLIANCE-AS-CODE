# OPA/Rego Policy for Networking Compliance
# Maps to CIS AWS Benchmark 5.x controls

package terraform.networking

import future.keywords.in

# Default deny
default allow = false

# Admin ports that should never be open to the world
admin_ports := [22, 3389]
database_ports := [3306, 5432, 1433, 1521, 27017, 6379, 5439]
all_sensitive_ports := array.concat(admin_ports, database_ports)

# =============================================================================
# CIS 5.1: NACLs - No ingress from 0.0.0.0/0 to admin ports
# =============================================================================

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_network_acl_rule"
    rule := resource.change.after

    rule.egress == false  # Ingress rule
    rule.rule_action == "allow"
    is_open_cidr(rule.cidr_block)
    port_in_range(rule.from_port, rule.to_port, admin_ports)

    msg := sprintf(
        "CIS-AWS-5.1 CRITICAL: NACL rule '%s' allows ingress from 0.0.0.0/0 to admin ports (22, 3389). Block this access.",
        [resource.address]
    )
}

# =============================================================================
# CIS 5.2: Security Groups - No ingress from 0.0.0.0/0 to admin ports
# =============================================================================

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group"
    sg := resource.change.after

    ingress := sg.ingress[_]
    cidr := ingress.cidr_blocks[_]
    is_open_cidr(cidr)
    port_in_range(ingress.from_port, ingress.to_port, admin_ports)

    msg := sprintf(
        "CIS-AWS-5.2 CRITICAL: Security group '%s' allows SSH/RDP from 0.0.0.0/0. Restrict to specific IP ranges.",
        [resource.address]
    )
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group_rule"
    rule := resource.change.after

    rule.type == "ingress"
    cidr := rule.cidr_blocks[_]
    is_open_cidr(cidr)
    port_in_range(rule.from_port, rule.to_port, admin_ports)

    msg := sprintf(
        "CIS-AWS-5.2 CRITICAL: Security group rule '%s' allows SSH/RDP from 0.0.0.0/0",
        [resource.address]
    )
}

# =============================================================================
# CIS 5.3: Default Security Group Restricts All Traffic
# =============================================================================

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_default_security_group"
    sg := resource.change.after

    count(sg.ingress) > 0

    msg := sprintf(
        "CIS-AWS-5.3 HIGH: Default security group '%s' has ingress rules. Default SG should restrict all traffic.",
        [resource.address]
    )
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_default_security_group"
    sg := resource.change.after

    count(sg.egress) > 0

    msg := sprintf(
        "CIS-AWS-5.3 HIGH: Default security group '%s' has egress rules. Default SG should restrict all traffic.",
        [resource.address]
    )
}

# =============================================================================
# CIS 5.5: NACLs - Block SSH and RDP from 0.0.0.0/0
# =============================================================================

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_network_acl"
    nacl := resource.change.after

    ingress := nacl.ingress[_]
    ingress.action == "allow"
    is_open_cidr(ingress.cidr_block)
    port_in_range(ingress.from_port, ingress.to_port, [22])

    msg := sprintf(
        "CIS-AWS-5.5 CRITICAL: NACL '%s' allows SSH (port 22) from 0.0.0.0/0",
        [resource.address]
    )
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_network_acl"
    nacl := resource.change.after

    ingress := nacl.ingress[_]
    ingress.action == "allow"
    is_open_cidr(ingress.cidr_block)
    port_in_range(ingress.from_port, ingress.to_port, [3389])

    msg := sprintf(
        "CIS-AWS-5.5 CRITICAL: NACL '%s' allows RDP (port 3389) from 0.0.0.0/0",
        [resource.address]
    )
}

# =============================================================================
# CIS 5.6: EC2 Metadata Service - IMDSv2 Required
# =============================================================================

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_instance"
    instance := resource.change.after

    not imdsv2_required(instance)

    msg := sprintf(
        "CIS-AWS-5.6 HIGH: EC2 instance '%s' does not require IMDSv2. Set http_tokens = 'required' in metadata_options.",
        [resource.address]
    )
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_launch_template"
    template := resource.change.after

    not imdsv2_required_template(template)

    msg := sprintf(
        "CIS-AWS-5.6 HIGH: Launch template '%s' does not require IMDSv2. Set http_tokens = 'required'.",
        [resource.address]
    )
}

imdsv2_required(instance) {
    instance.metadata_options[_].http_tokens == "required"
}

imdsv2_required_template(template) {
    template.metadata_options[_].http_tokens == "required"
}

# =============================================================================
# Best Practice: Restrict Database Ports
# =============================================================================

warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group"
    sg := resource.change.after

    ingress := sg.ingress[_]
    cidr := ingress.cidr_blocks[_]
    is_open_cidr(cidr)
    port_in_range(ingress.from_port, ingress.to_port, database_ports)

    msg := sprintf(
        "BEST-PRACTICE HIGH: Security group '%s' allows database access from 0.0.0.0/0. Restrict to application subnets.",
        [resource.address]
    )
}

# =============================================================================
# Best Practice: VPC Peering Least Privilege
# =============================================================================

warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_route"
    route := resource.change.after

    route.vpc_peering_connection_id != null
    route.destination_cidr_block == "0.0.0.0/0"

    msg := sprintf(
        "CIS-AWS-5.4 MEDIUM: VPC peering route '%s' has destination 0.0.0.0/0. Use least-access routing.",
        [resource.address]
    )
}

# =============================================================================
# Best Practice: No All-Traffic Security Group Rules
# =============================================================================

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group"
    sg := resource.change.after

    ingress := sg.ingress[_]
    cidr := ingress.cidr_blocks[_]
    is_open_cidr(cidr)
    ingress.from_port == 0
    ingress.to_port == 65535
    ingress.protocol == "-1"

    msg := sprintf(
        "BEST-PRACTICE CRITICAL: Security group '%s' allows ALL traffic from 0.0.0.0/0. This is extremely dangerous.",
        [resource.address]
    )
}

# =============================================================================
# Helper Functions
# =============================================================================

# Check if CIDR is open to the world
is_open_cidr(cidr) {
    cidr == "0.0.0.0/0"
}

is_open_cidr(cidr) {
    cidr == "::/0"
}

# Check if any sensitive port is in the range
port_in_range(from_port, to_port, ports) {
    port := ports[_]
    from_port <= port
    to_port >= port
}

# =============================================================================
# Compliance Summary
# =============================================================================

compliance_summary[control] {
    control := {
        "standard": "CIS AWS Foundations Benchmark v1.5.0",
        "section": "5. Networking",
        "controls_checked": ["5.1", "5.2", "5.3", "5.4", "5.5", "5.6"]
    }
}
