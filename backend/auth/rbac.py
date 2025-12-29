"""
RBAC (Role-Based Access Control) System
"""

from enum import Enum
from typing import List
from fastapi import HTTPException, status


class Permission(str, Enum):
    """System permissions"""
    # Scan permissions
    SCAN_VIEW = "scan:view"
    SCAN_CREATE = "scan:create"
    SCAN_DELETE = "scan:delete"
    
    # Finding permissions
    FINDING_VIEW = "finding:view"
    FINDING_UPDATE = "finding:update"
    FINDING_DELETE = "finding:delete"
    
    # Exception permissions
    EXCEPTION_VIEW = "exception:view"
    EXCEPTION_CREATE = "exception:create"
    EXCEPTION_APPROVE = "exception:approve"
    EXCEPTION_REJECT = "exception:reject"
    
    # Remediation permissions
    REMEDIATE_VIEW = "remediate:view"
    REMEDIATE_EXECUTE = "remediate:execute"
    
    # Report permissions
    REPORT_VIEW = "report:view"
    REPORT_GENERATE = "report:generate"
    
    # User management
    USER_VIEW = "user:view"
    USER_CREATE = "user:create"
    USER_UPDATE = "user:update"
    USER_DELETE = "user:delete"
    
    # Settings
    SETTINGS_VIEW = "settings:view"
    SETTINGS_UPDATE = "settings:update"
    
    # Audit logs
    AUDIT_VIEW = "audit:view"


# Role to Permissions mapping
ROLE_PERMISSIONS = {
    "admin": [
        # Admin has all permissions
        Permission.SCAN_VIEW,
        Permission.SCAN_CREATE,
        Permission.SCAN_DELETE,
        Permission.FINDING_VIEW,
        Permission.FINDING_UPDATE,
        Permission.FINDING_DELETE,
        Permission.EXCEPTION_VIEW,
        Permission.EXCEPTION_CREATE,
        Permission.EXCEPTION_APPROVE,
        Permission.EXCEPTION_REJECT,
        Permission.REMEDIATE_VIEW,
        Permission.REMEDIATE_EXECUTE,
        Permission.REPORT_VIEW,
        Permission.REPORT_GENERATE,
        Permission.USER_VIEW,
        Permission.USER_CREATE,
        Permission.USER_UPDATE,
        Permission.USER_DELETE,
        Permission.SETTINGS_VIEW,
        Permission.SETTINGS_UPDATE,
        Permission.AUDIT_VIEW,
    ],
    
    "security_engineer": [
        # Security Engineer - operational permissions
        Permission.SCAN_VIEW,
        Permission.SCAN_CREATE,
        Permission.FINDING_VIEW,
        Permission.FINDING_UPDATE,
        Permission.EXCEPTION_VIEW,
        Permission.EXCEPTION_CREATE,
        Permission.EXCEPTION_APPROVE,  # Can approve own team's exceptions
        Permission.REMEDIATE_VIEW,
        Permission.REMEDIATE_EXECUTE,
        Permission.REPORT_VIEW,
        Permission.REPORT_GENERATE,
        Permission.USER_VIEW,
        Permission.SETTINGS_VIEW,
        Permission.AUDIT_VIEW,
    ],
    
    "auditor": [
        # Auditor - read-only permissions
        Permission.SCAN_VIEW,
        Permission.FINDING_VIEW,
        Permission.EXCEPTION_VIEW,
        Permission.REMEDIATE_VIEW,
        Permission.REPORT_VIEW,
        Permission.REPORT_GENERATE,
        Permission.AUDIT_VIEW,
    ],
    
    "customer": [
        # Customer - limited view permissions
        Permission.SCAN_VIEW,
        Permission.FINDING_VIEW,
        Permission.REPORT_VIEW,
    ],
}


class RBACChecker:
    """Role-Based Access Control checker"""
    
    @staticmethod
    def has_permission(role: str, permission: Permission) -> bool:
        """
        Check if a role has a specific permission
        
        Args:
            role: User role
            permission: Required permission
            
        Returns:
            True if role has permission, False otherwise
        """
        role_perms = ROLE_PERMISSIONS.get(role, [])
        return permission in role_perms
    
    @staticmethod
    def require_permission(role: str, permission: Permission):
        """
        Raise HTTPException if role doesn't have permission
        
        Args:
            role: User role
            permission: Required permission
            
        Raises:
            HTTPException: 403 Forbidden if permission denied
        """
        if not RBACChecker.has_permission(role, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied. Required permission: {permission.value}"
            )
    
    @staticmethod
    def require_any_permission(role: str, permissions: List[Permission]):
        """
        Require at least one of the listed permissions
        
        Args:
            role: User role
            permissions: List of acceptable permissions
            
        Raises:
            HTTPException: 403 Forbidden if no permission matches
        """
        for permission in permissions:
            if RBACChecker.has_permission(role, permission):
                return
        
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission denied. Required one of: {[p.value for p in permissions]}"
        )
    
    @staticmethod
    def require_all_permissions(role: str, permissions: List[Permission]):
        """
        Require all listed permissions
        
        Args:
            role: User role
            permissions: List of required permissions
            
        Raises:
            HTTPException: 403 Forbidden if any permission missing
        """
        for permission in permissions:
            RBACChecker.require_permission(role, permission)


# Convenience functions
def has_permission(role: str, permission: Permission) -> bool:
    """Check if role has permission"""
    return RBACChecker.has_permission(role, permission)


def require_permission(role: str, permission: Permission):
    """Require specific permission"""
    RBACChecker.require_permission(role, permission)


def require_admin(role: str):
    """Require admin role"""
    if role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )


def require_security_engineer_or_admin(role: str):
    """Require security engineer or admin role"""
    if role not in ["admin", "security_engineer"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Security Engineer or Admin access required"
        )
