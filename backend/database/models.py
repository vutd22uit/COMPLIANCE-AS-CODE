"""
SQLAlchemy Database Models for Enterprise Compliance Platform
"""

from datetime import datetime
from typing import Optional
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Boolean, 
    ForeignKey, Enum, JSON, Float, Index
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import enum

Base = declarative_base()


# ============================================
# Enums
# ============================================

class UserRole(str, enum.Enum):
    ADMIN = "admin"
    SECURITY_ENGINEER = "security_engineer"
    AUDITOR = "auditor"
    CUSTOMER = "customer"


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FindingStatus(str, enum.Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    EXCEPTION = "exception"
    FALSE_POSITIVE = "false_positive"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ExceptionStatus(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class RemediationStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"


# ============================================
# Models
# ============================================

class Organization(Base):
    """Organizations/Tenants in the system"""
    __tablename__ = "organizations"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, nullable=False, index=True)
    type = Column(String(100))  # cloud_provider, enterprise, bank, etc.
    description = Column(Text)
    settings = Column(JSON)  # Custom settings per org
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    users = relationship("User", back_populates="organization")
    environments = relationship("Environment", back_populates="organization")
    scan_jobs = relationship("ScanJob", back_populates="organization")


class User(Base):
    """Users in the system"""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255))
    role = Column(Enum(UserRole), nullable=False, default=UserRole.AUDITOR)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    active = Column(Boolean, default=True)
    last_login = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    organization = relationship("Organization", back_populates="users")
    audit_logs = relationship("AuditLog", back_populates="user")
    exceptions_created = relationship("Exception", foreign_keys="Exception.created_by_id", back_populates="created_by")
    exceptions_approved = relationship("Exception", foreign_keys="Exception.approved_by_id", back_populates="approved_by")


class Environment(Base):
    """OpenStack environments being monitored"""
    __tablename__ = "environments"
    
    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    name = Column(String(255), nullable=False, index=True)
    type = Column(String(100))  # production, staging, development
    description = Column(Text)
    
    # Connection details
    controller_host = Column(String(255))
    ssh_user = Column(String(100))
    ssh_key_path = Column(String(500))
    
    # OpenStack info
    openstack_version = Column(String(50))
    deployment_method = Column(String(50))  # kolla-ansible, tripleo, etc.
    
    # Compliance settings
    compliance_standards = Column(JSON)  # ["CIS OpenStack", "CIS Linux", "PCI-DSS"]
    scan_schedule = Column(String(100))  # Cron expression
    
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    organization = relationship("Organization", back_populates="environments")
    scan_jobs = relationship("ScanJob", back_populates="environment")


class ScanJob(Base):
    """Compliance scan jobs"""
    __tablename__ = "scan_jobs"
    
    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    environment_id = Column(Integer, ForeignKey("environments.id"), nullable=False)
    
    scan_type = Column(String(100), nullable=False)  # openstack, linux, full
    status = Column(Enum(ScanStatus), nullable=False, default=ScanStatus.PENDING, index=True)
    
    # Execution details
    scheduled_time = Column(DateTime)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    duration_seconds = Column(Integer)
    
    # Results
    evidence_id = Column(String(255), unique=True, index=True)
    evidence_path = Column(String(500))
    result_summary = Column(JSON)  # {total, passed, failed, skipped, score}
    
    # Error handling
    error_message = Column(Text)
    retry_count = Column(Integer, default=0)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    organization = relationship("Organization", back_populates="scan_jobs")
    environment = relationship("Environment", back_populates="scan_jobs")
    findings = relationship("Finding", back_populates="scan_job")
    
    # Indexes
    __table_args__ = (
        Index('idx_scan_status_time', 'status', 'scheduled_time'),
    )


class Finding(Base):
    """Compliance findings/violations"""
    __tablename__ = "findings"
    
    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(String(255), unique=True, nullable=False, index=True)
    
    # Source
    scan_job_id = Column(Integer, ForeignKey("scan_jobs.id"), nullable=False)
    evidence_id = Column(String(255), index=True)
    
    # Control information
    control_id = Column(String(100), nullable=False, index=True)
    control_title = Column(String(500))
    control_description = Column(Text)
    standard = Column(String(100))  # CIS OpenStack Benchmark
    section = Column(String(255), index=True)  # 1. Identity (Keystone)
    
    # Severity and status
    severity = Column(Enum(Severity), nullable=False, index=True)
    status = Column(Enum(FindingStatus), nullable=False, default=FindingStatus.OPEN, index=True)
    
    # Resource information
    resource_type = Column(String(100), index=True)  # keystone, nova, neutron
    resource_id = Column(String(255))
    resource_name = Column(String(255))
    config_file = Column(String(500))
    hostname = Column(String(255))
    
    # Evidence
    actual_value = Column(Text)
    expected_value = Column(Text)
    evidence_message = Column(Text)
    code_description = Column(Text)
    
    # Remediation
    auto_remediable = Column(Boolean, default=False)
    remediation_method = Column(String(100))  # ansible, manual
    remediation_playbook = Column(String(500))
    
    # Tracking
    first_seen = Column(DateTime, default=datetime.utcnow, index=True)
    last_seen = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime)
    
    # Metadata
    false_positive = Column(Boolean, default=False)
    notes = Column(Text)
    extra_metadata = Column(JSON)  # Renamed from 'metadata' (reserved word)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    scan_job = relationship("ScanJob", back_populates="findings")
    exception = relationship("Exception", uselist=False, back_populates="finding")
    remediation_tasks = relationship("RemediationTask", back_populates="finding")
    
    # Indexes
    __table_args__ = (
        Index('idx_finding_status_severity', 'status', 'severity'),
        Index('idx_finding_control_status', 'control_id', 'status'),
    )


class Exception(Base):
    """Compliance exceptions/waivers"""
    __tablename__ = "exceptions"
    
    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), unique=True, nullable=False)
    
    # Exception details
    reason = Column(Text, nullable=False)
    business_justification = Column(Text)
    compensating_controls = Column(Text)
    
    # Approval workflow
    status = Column(Enum(ExceptionStatus), nullable=False, default=ExceptionStatus.PENDING, index=True)
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    approved_by_id = Column(Integer, ForeignKey("users.id"))
    approval_comments = Column(Text)
    
    # Expiry
    expiry_date = Column(DateTime, nullable=False, index=True)
    auto_extend = Column(Boolean, default=False)
    
    # Tracking
    created_at = Column(DateTime, default=datetime.utcnow)
    approved_at = Column(DateTime)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    finding = relationship("Finding", back_populates="exception")
    created_by = relationship("User", foreign_keys=[created_by_id], back_populates="exceptions_created")
    approved_by = relationship("User", foreign_keys=[approved_by_id], back_populates="exceptions_approved")


class RemediationTask(Base):
    """Remediation task executions"""
    __tablename__ = "remediation_tasks"
    
    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=False)
    
    # Task details
    task_type = Column(String(100))  # ansible, manual
    playbook = Column(String(500))
    playbook_tags = Column(String(255))
    
    # Execution
    status = Column(Enum(RemediationStatus), nullable=False, default=RemediationStatus.PENDING, index=True)
    executed_by = Column(String(100))
    executed_at = Column(DateTime)
    completed_at = Column(DateTime)
    duration_seconds = Column(Integer)
    
    # Results
    output = Column(Text)
    error_message = Column(Text)
    changes_made = Column(JSON)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    finding = relationship("Finding", back_populates="remediation_tasks")


class ComplianceSnapshot(Base):
    """Daily/weekly compliance snapshots"""
    __tablename__ = "compliance_snapshots"
    
    id = Column(Integer, primary_key=True, index=True)
    snapshot_id = Column(String(255), unique=True, nullable=False, index=True)
    
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    environment_id = Column(Integer, ForeignKey("environments.id"))
    
    snapshot_type = Column(String(50))  # daily, weekly, monthly
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Overall statistics
    overall_score = Column(Float)
    total_controls = Column(Integer)
    controls_passed = Column(Integer)
    controls_failed = Column(Integer)
    controls_excepted = Column(Integer)
    
    # By severity
    critical_findings = Column(Integer)
    high_findings = Column(Integer)
    medium_findings = Column(Integer)
    low_findings = Column(Integer)
    
    # By section (JSON data)
    by_section = Column(JSON)
    by_service = Column(JSON)
    
    # Trends
    score_change = Column(Float)  # Compared to previous snapshot
    new_findings = Column(Integer)
    resolved_findings = Column(Integer)
    
    # Top violations
    top_violations = Column(JSON)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_snapshot_org_time', 'organization_id', 'timestamp'),
    )


class AuditLog(Base):
    """Audit trail for all system actions"""
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Who
    user_id = Column(Integer, ForeignKey("users.id"))
    username = Column(String(100), index=True)
    ip_address = Column(String(45))
    
    # What
    action = Column(String(100), nullable=False, index=True)  # login, create_exception, approve_exception
    resource_type = Column(String(100), index=True)  # user, finding, exception
    resource_id = Column(String(255))
    
    # Details
    details = Column(JSON)
    old_values = Column(JSON)
    new_values = Column(JSON)
    
    # When
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Result
    success = Column(Boolean, default=True)
    error_message = Column(Text)
    
    # Relationships
    user = relationship("User", back_populates="audit_logs")
    
    __table_args__ = (
        Index('idx_audit_user_time', 'user_id', 'timestamp'),
        Index('idx_audit_action_time', 'action', 'timestamp'),
    )


class Integration(Base):
    """External integrations (Jira, Slack, etc.)"""
    __tablename__ = "integrations"
    
    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    
    type = Column(String(50), nullable=False)  # jira, slack, teams, webhook
    name = Column(String(255), nullable=False)
    enabled = Column(Boolean, default=True)
    
    # Configuration (encrypted in production)
    config = Column(JSON)  # {url, auth_token, project_key, etc.}
    
    # Trigger settings
    triggers = Column(JSON)  # {on_new_finding: true, severity_filter: ["CRITICAL"]}
    
    # Status
    last_success = Column(DateTime)
    last_error = Column(Text)
    total_calls = Column(Integer, default=0)
    failed_calls = Column(Integer, default=0)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SLAPolicy(Base):
    """SLA policies for remediation"""
    __tablename__ = "sla_policies"
    
    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    
    name = Column(String(255), nullable=False)
    severity = Column(Enum(Severity), nullable=False, index=True)
    
    # SLA targets (in hours)
    detection_sla = Column(Integer)  # Time to detect (already happened)
    acknowledgment_sla = Column(Integer)  # Time to acknowledge
    remediation_sla = Column(Integer)  # Time to remediate
    
    # Escalation
    escalation_enabled = Column(Boolean, default=False)
    escalation_after_hours = Column(Integer)
    escalation_emails = Column(JSON)
    
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
