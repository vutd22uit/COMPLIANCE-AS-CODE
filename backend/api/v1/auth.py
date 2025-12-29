"""Authentication API Endpoints"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import Optional

from backend.database.database import get_db
from backend.database.models import User, UserRole
from backend.auth.jwt_handler import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    verify_token
)
from backend.auth.dependencies import get_current_user

router = APIRouter()


# ============================================
# Pydantic Models (Request/Response)
# ============================================

class LoginRequest(BaseModel):
    """Login request payload"""
    username: str
    password: str


class TokenResponse(BaseModel):
    """Token response"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 3600  # seconds
    user: dict


class RefreshTokenRequest(BaseModel):
    """Refresh token request"""
    refresh_token: str


class ChangePasswordRequest(BaseModel):
    """Change password request"""
    current_password: str
    new_password: str


class UserResponse(BaseModel):
    """User response model"""
    id: int
    username: str
    email: str
    full_name: Optional[str]
    role: str
    organization_id: int
    active: bool
    last_login: Optional[datetime]
    created_at: datetime
    
    class Config:
        from_attributes = True


# ============================================
# Endpoints
# ============================================

@router.post("/login", response_model=TokenResponse, status_code=status.HTTP_200_OK)
async def login(
    login_data: LoginRequest,
    db: Session = Depends(get_db)
):
    """
    **User Login**
    
    Authenticate user with username and password, return JWT tokens.
    
    - **username**: User's username
    - **password**: User's password
    
    Returns:
    - **access_token**: JWT access token (valid for 1 hour)
    - **refresh_token**: JWT refresh token (valid for 7 days)
    - **user**: User information
    """
    # Find user
    user = db.query(User).filter(User.username == login_data.username).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Verify password
    if not verify_password(login_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Check if user is active
    if not user.active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled"
        )
    
    # Create tokens
    token_data = {
        "user_id": user.id,
        "username": user.username,
        "role": user.role.value,
        "organization_id": user.organization_id
    }
    
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token({"user_id": user.id})
    
    # Update last login
    user.last_login = datetime.utcnow()
    db.commit()
    
    # Build response
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user={
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role.value,
            "organization_id": user.organization_id
        }
    )


@router.post("/refresh", response_model=TokenResponse, status_code=status.HTTP_200_OK)
async def refresh_access_token(
    refresh_data: RefreshTokenRequest,
    db: Session = Depends(get_db)
):
    """
    **Refresh Access Token**
    
    Use refresh token to obtain a new access token.
    
    - **refresh_token**: Valid refresh token from login
    
    Returns:
    - New access token and refresh token
    """
    # Verify refresh token
    from backend.auth.jwt_handler import JWTHandler
    payload = JWTHandler.verify_token(refresh_data.refresh_token, "refresh")
    
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Get user
    user_id = payload.get("user_id")
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user or not user.active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create new tokens
    token_data = {
        "user_id": user.id,
        "username": user.username,
        "role": user.role.value,
        "organization_id": user.organization_id
    }
    
    access_token = create_access_token(token_data)
    new_refresh_token = create_refresh_token({"user_id": user.id})
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
        user={
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role.value,
            "organization_id": user.organization_id
        }
    )


@router.get("/me", response_model=UserResponse, status_code=status.HTTP_200_OK)
async def get_current_user_info(
    current_user: User = Depends(get_current_user)
):
    """
    **Get Current User**
    
    Get information about the currently authenticated user.
    
    Requires: Valid JWT token in Authorization header
    """
    return UserResponse(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        full_name=current_user.full_name,
        role=current_user.role.value,
        organization_id=current_user.organization_id,
        active=current_user.active,
        last_login=current_user.last_login,
        created_at=current_user.created_at
    )


@router.post("/change-password", status_code=status.HTTP_200_OK)
async def change_password(
    password_data: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    **Change Password**
    
    Change the current user's password.
    
    - **current_password**: User's current password
    - **new_password**: New password (minimum 8 characters recommended)
    """
    # Verify current password
    if not verify_password(password_data.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )
    
    # Validate new password (add more validation as needed)
    if len(password_data.new_password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be at least 8 characters long"
        )
    
    # Hash and update password
    current_user.hashed_password = hash_password(password_data.new_password)
    db.commit()
    
    return {"message": "Password changed successfully"}


@router.post("/logout", status_code=status.HTTP_200_OK)
async def logout(current_user: User = Depends(get_current_user)):
    """
    **Logout**
    
    Logout current user.
    Note: JWT tokens are stateless, so client should discard the token.
    For proper logout, implement token blacklisting if needed.
    """
    # In production, you might want to:
    # 1. Add token to blacklist/revocation list
    # 2. Store in Redis with expiration time
    # 3. Client should delete the token from storage
    
    return {
        "message": "Logged out successfully",
        "note": "Please discard the access token on the client side"
    }
