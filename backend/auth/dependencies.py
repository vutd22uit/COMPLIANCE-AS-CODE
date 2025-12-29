"""
FastAPI Dependencies for Authentication and Authorization
"""

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from typing import Optional

from backend.database.database import get_db
from backend.database.models import User, UserRole
from backend.auth.jwt_handler import verify_token
from backend.auth.rbac import Permission, require_permission

# HTTP Bearer token security scheme
security = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """
    Get current authenticated user from JWT token
    
    Args:
        credentials: HTTP Bearer token
        db: Database session
        
    Returns:
        User object
        
    Raises:
        HTTPException: 401 if token invalid or user not found
    """
    token = credentials.credentials
    
    # Verify token
    payload = verify_token(token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Extract user ID
    user_id: int = payload.get("user_id")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Get user from database
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Check if user is active
    if not user.active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled"
        )
    
    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Get current active user (additional check)
    
    Args:
        current_user: Current user from token
        
    Returns:
        Active user object
    """
    if not current_user.active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )
    return current_user


async def get_current_admin_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Require admin role
    
    Args:
        current_user: Current user from token
        
    Returns:
        Admin user object
        
    Raises:
        HTTPException: 403 if not admin
    """
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user


async def get_current_security_engineer(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Require security engineer or admin role
    
    Args:
        current_user: Current user from token
        
    Returns:
        Security engineer or admin user
        
    Raises:
        HTTPException: 403 if not authorized
    """
    if current_user.role not in [UserRole.ADMIN, UserRole.SECURITY_ENGINEER]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Security Engineer or Admin access required"
        )
    return current_user


def require_role(required_role: UserRole):
    """
    Dependency factory to require specific role
    
    Usage:
        @app.get("/admin-only")
        def admin_endpoint(user: User = Depends(require_role(UserRole.ADMIN))):
            return {"message": "Admin access granted"}
    
    Args:
        required_role: Required user role
        
    Returns:
        Dependency function
    """
    async def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role != required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required role: {required_role.value}"
            )
        return current_user
    
    return role_checker


def require_permission_dependency(permission: Permission):
    """
    Dependency factory to require specific permission
    
    Usage:
        @app.delete("/findings/{id}")
        def delete_finding(
            finding_id: int,
            user: User = Depends(require_permission_dependency(Permission.FINDING_DELETE))
        ):
            # Delete finding
            return {"status": "deleted"}
    
    Args:
        permission: Required permission
        
    Returns:
        Dependency function
    """
    async def permission_checker(current_user: User = Depends(get_current_user)) -> User:
        require_permission(current_user.role.value, permission)
        return current_user
    
    return permission_checker


# Optional authentication (for public endpoints that benefit from auth)
async def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False)),
    db: Session = Depends(get_db)
) -> Optional[User]:
    """
    Get current user if token provided, otherwise None
    
    Args:
        credentials: Optional HTTP Bearer token
        db: Database session
        
    Returns:
        User object or None
    """
    if credentials is None:
        return None
    
    try:
        token = credentials.credentials
        payload = verify_token(token)
        
        if payload is None:
            return None
        
        user_id = payload.get("user_id")
        if user_id is None:
            return None
        
        user = db.query(User).filter(User.id == user_id).first()
        return user if user and user.active else None
    
    except Exception:
        return None
