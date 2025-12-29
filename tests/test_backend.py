"""
Unit Tests for Backend API
"""

import pytest
from datetime import datetime
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


# ============================================
# Test: Database Models
# ============================================

class TestDatabaseModels:
    """Test database model definitions"""
    
    def test_import_models(self):
        """Test that all models can be imported"""
        from backend.database.models import (
            Organization, User, UserRole,
            Environment, ScanJob, ScanStatus,
            Finding, FindingStatus, Severity,
            Exception, ExceptionStatus,
            RemediationTask, RemediationStatus,
            ComplianceSnapshot, AuditLog,
            Integration, SLAPolicy
        )
        
        # Verify enums
        assert UserRole.ADMIN.value == "admin"
        assert UserRole.SECURITY_ENGINEER.value == "security_engineer"
        assert UserRole.AUDITOR.value == "auditor"
        assert UserRole.CUSTOMER.value == "customer"
        
        # Verify scan status
        assert ScanStatus.PENDING.value == "pending"
        assert ScanStatus.RUNNING.value == "running"
        assert ScanStatus.COMPLETED.value == "completed"
        assert ScanStatus.FAILED.value == "failed"
        
        # Verify finding status
        assert FindingStatus.OPEN.value == "open"
        assert FindingStatus.RESOLVED.value == "resolved"
        
        # Verify severity
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        
        print("✅ All models imported successfully")
    
    def test_model_columns(self):
        """Test that models have required columns"""
        from backend.database.models import User, Organization, Finding
        
        # Check User model
        assert hasattr(User, 'id')
        assert hasattr(User, 'username')
        assert hasattr(User, 'email')
        assert hasattr(User, 'hashed_password')
        assert hasattr(User, 'role')
        assert hasattr(User, 'organization_id')
        
        # Check Organization model
        assert hasattr(Organization, 'id')
        assert hasattr(Organization, 'name')
        assert hasattr(Organization, 'type')
        
        # Check Finding model
        assert hasattr(Finding, 'id')
        assert hasattr(Finding, 'finding_id')
        assert hasattr(Finding, 'control_id')
        assert hasattr(Finding, 'severity')
        assert hasattr(Finding, 'status')
        
        print("✅ All model columns verified")


# ============================================
# Test: JWT Handler
# ============================================

class TestJWTHandler:
    """Test JWT authentication functions"""
    
    def test_password_hashing(self):
        """Test password hashing and verification"""
        from backend.auth.jwt_handler import hash_password, verify_password
        
        password = "TestPassword123!"
        hashed = hash_password(password)
        
        # Hash should be different from original
        assert hashed != password
        
        # Verify correct password
        assert verify_password(password, hashed) == True
        
        # Verify wrong password
        assert verify_password("WrongPassword", hashed) == False
        
        print("✅ Password hashing works correctly")
    
    def test_access_token_creation(self):
        """Test JWT access token creation"""
        from backend.auth.jwt_handler import create_access_token, verify_token
        
        data = {
            "user_id": 1,
            "username": "testuser",
            "role": "admin"
        }
        
        token = create_access_token(data)
        
        # Token should be a string
        assert isinstance(token, str)
        assert len(token) > 50
        
        # Verify token
        payload = verify_token(token)
        assert payload is not None
        assert payload.get("user_id") == 1
        assert payload.get("username") == "testuser"
        assert payload.get("role") == "admin"
        
        print("✅ Access token creation works correctly")
    
    def test_refresh_token_creation(self):
        """Test JWT refresh token creation"""
        from backend.auth.jwt_handler import create_refresh_token, JWTHandler
        
        data = {"user_id": 1}
        
        token = create_refresh_token(data)
        
        # Token should be a string
        assert isinstance(token, str)
        
        # Verify refresh token
        payload = JWTHandler.verify_token(token, "refresh")
        assert payload is not None
        assert payload.get("user_id") == 1
        assert payload.get("type") == "refresh"
        
        print("✅ Refresh token creation works correctly")
    
    def test_invalid_token(self):
        """Test invalid token verification"""
        from backend.auth.jwt_handler import verify_token
        
        # Test completely invalid token
        result = verify_token("invalid.token.here")
        assert result is None
        
        # Test empty token
        result = verify_token("")
        assert result is None
        
        print("✅ Invalid token handling works correctly")


# ============================================
# Test: RBAC System
# ============================================

class TestRBAC:
    """Test Role-Based Access Control"""
    
    def test_admin_permissions(self):
        """Test admin has all permissions"""
        from backend.auth.rbac import has_permission, Permission
        
        # Admin should have all permissions
        assert has_permission("admin", Permission.SCAN_VIEW) == True
        assert has_permission("admin", Permission.SCAN_CREATE) == True
        assert has_permission("admin", Permission.SCAN_DELETE) == True
        assert has_permission("admin", Permission.FINDING_VIEW) == True
        assert has_permission("admin", Permission.FINDING_DELETE) == True
        assert has_permission("admin", Permission.EXCEPTION_APPROVE) == True
        assert has_permission("admin", Permission.USER_CREATE) == True
        assert has_permission("admin", Permission.USER_DELETE) == True
        assert has_permission("admin", Permission.SETTINGS_UPDATE) == True
        
        print("✅ Admin has all permissions")
    
    def test_security_engineer_permissions(self):
        """Test security engineer permissions"""
        from backend.auth.rbac import has_permission, Permission
        
        # Security engineer should have operational permissions
        assert has_permission("security_engineer", Permission.SCAN_VIEW) == True
        assert has_permission("security_engineer", Permission.SCAN_CREATE) == True
        assert has_permission("security_engineer", Permission.FINDING_VIEW) == True
        assert has_permission("security_engineer", Permission.EXCEPTION_CREATE) == True
        assert has_permission("security_engineer", Permission.REMEDIATE_EXECUTE) == True
        
        # But not admin-only permissions
        assert has_permission("security_engineer", Permission.SCAN_DELETE) == False
        assert has_permission("security_engineer", Permission.USER_DELETE) == False
        assert has_permission("security_engineer", Permission.SETTINGS_UPDATE) == False
        
        print("✅ Security engineer permissions verified")
    
    def test_auditor_permissions(self):
        """Test auditor permissions (read-only)"""
        from backend.auth.rbac import has_permission, Permission
        
        # Auditor should have read-only permissions
        assert has_permission("auditor", Permission.SCAN_VIEW) == True
        assert has_permission("auditor", Permission.FINDING_VIEW) == True
        assert has_permission("auditor", Permission.REPORT_VIEW) == True
        assert has_permission("auditor", Permission.REPORT_GENERATE) == True
        assert has_permission("auditor", Permission.AUDIT_VIEW) == True
        
        # But not write permissions
        assert has_permission("auditor", Permission.SCAN_CREATE) == False
        assert has_permission("auditor", Permission.FINDING_UPDATE) == False
        assert has_permission("auditor", Permission.EXCEPTION_CREATE) == False
        
        print("✅ Auditor permissions verified (read-only)")
    
    def test_customer_permissions(self):
        """Test customer permissions (most limited)"""
        from backend.auth.rbac import has_permission, Permission
        
        # Customer should have very limited permissions
        assert has_permission("customer", Permission.SCAN_VIEW) == True
        assert has_permission("customer", Permission.FINDING_VIEW) == True
        assert has_permission("customer", Permission.REPORT_VIEW) == True
        
        # But not much else
        assert has_permission("customer", Permission.SCAN_CREATE) == False
        assert has_permission("customer", Permission.EXCEPTION_CREATE) == False
        assert has_permission("customer", Permission.AUDIT_VIEW) == False
        
        print("✅ Customer permissions verified (limited)")
    
    def test_invalid_role(self):
        """Test unknown role has no permissions"""
        from backend.auth.rbac import has_permission, Permission
        
        assert has_permission("unknown_role", Permission.SCAN_VIEW) == False
        assert has_permission("hacker", Permission.USER_DELETE) == False
        
        print("✅ Invalid roles handled correctly")


# ============================================
# Test: Pydantic Models
# ============================================

class TestPydanticModels:
    """Test API request/response models"""
    
    def test_login_request(self):
        """Test login request validation"""
        from backend.api.v1.auth import LoginRequest
        
        # Valid request
        request = LoginRequest(username="admin", password="Admin@123")
        assert request.username == "admin"
        assert request.password == "Admin@123"
        
        print("✅ LoginRequest validation works")
    
    def test_token_response(self):
        """Test token response model"""
        from backend.api.v1.auth import TokenResponse
        
        response = TokenResponse(
            access_token="test_token",
            refresh_token="refresh_token",
            user={"id": 1, "username": "test"}
        )
        
        assert response.access_token == "test_token"
        assert response.token_type == "bearer"
        assert response.expires_in == 3600
        
        print("✅ TokenResponse validation works")
    
    def test_user_response(self):
        """Test user response model"""
        from backend.api.v1.auth import UserResponse
        
        response = UserResponse(
            id=1,
            username="admin",
            email="admin@test.com",
            full_name="Admin User",
            role="admin",
            organization_id=1,
            active=True,
            last_login=None,
            created_at=datetime.now()
        )
        
        assert response.id == 1
        assert response.username == "admin"
        assert response.role == "admin"
        
        print("✅ UserResponse validation works")


# ============================================
# Run All Tests
# ============================================

def run_all_tests():
    """Run all tests without pytest"""
    print("\n" + "="*60)
    print("🧪 RUNNING BACKEND UNIT TESTS")
    print("="*60 + "\n")
    
    failed = 0
    passed = 0
    
    # Test Database Models
    print("\n📦 Testing Database Models...")
    try:
        test_models = TestDatabaseModels()
        test_models.test_import_models()
        test_models.test_model_columns()
        passed += 2
    except Exception as e:
        print(f"❌ Database Models Test Failed: {e}")
        failed += 1
    
    # Test JWT Handler
    print("\n🔐 Testing JWT Handler...")
    try:
        test_jwt = TestJWTHandler()
        test_jwt.test_password_hashing()
        test_jwt.test_access_token_creation()
        test_jwt.test_refresh_token_creation()
        test_jwt.test_invalid_token()
        passed += 4
    except Exception as e:
        print(f"❌ JWT Handler Test Failed: {e}")
        failed += 1
    
    # Test RBAC
    print("\n👥 Testing RBAC System...")
    try:
        test_rbac = TestRBAC()
        test_rbac.test_admin_permissions()
        test_rbac.test_security_engineer_permissions()
        test_rbac.test_auditor_permissions()
        test_rbac.test_customer_permissions()
        test_rbac.test_invalid_role()
        passed += 5
    except Exception as e:
        print(f"❌ RBAC Test Failed: {e}")
        failed += 1
    
    # Test Pydantic Models
    print("\n📝 Testing Pydantic Models...")
    try:
        test_pydantic = TestPydanticModels()
        test_pydantic.test_login_request()
        test_pydantic.test_token_response()
        test_pydantic.test_user_response()
        passed += 3
    except Exception as e:
        print(f"❌ Pydantic Models Test Failed: {e}")
        failed += 1
    
    # Summary
    print("\n" + "="*60)
    print(f"📊 TEST RESULTS: {passed} passed, {failed} failed")
    print("="*60)
    
    if failed == 0:
        print("\n✅ ALL TESTS PASSED!")
        return True
    else:
        print(f"\n❌ {failed} TEST(S) FAILED!")
        return False


if __name__ == "__main__":
    success = run_all_tests()
    exit(0 if success else 1)
