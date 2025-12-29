"""
Database Initialization Script
Creates initial database schema and default admin user
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from datetime import datetime
from backend.database.database import create_tables, get_db_context
from backend.database.models import Organization, User, UserRole, Environment
from backend.auth.jwt_handler import hash_password

def init_database():
    """Initialize database with tables and default data"""
    
    print("🔧 Initializing database...")
    
    # Create all tables
    print("📋 Creating database tables...")
    create_tables()
    print("✅ Tables created successfully")
    
    # Create default data
    print("\n👤 Creating default admin user...")
    
    with get_db_context() as db:
        # Check if admin already exists
        existing_admin = db.query(User).filter(User.username == "admin").first()
        if existing_admin:
            print("⚠️  Admin user already exists, skipping...")
            return
        
        # Create default organization
        org = Organization(
            name="Default Organization",
            type="enterprise",
            description="Default organization created during initialization",
            settings={
                "compliance_standards": ["CIS OpenStack Benchmark", "CIS Linux Benchmark"],
                "default_scan_schedule": "0 2 * * *"  # Daily at 2 AM
            },
            active=True
        )
        db.add(org)
        db.flush()  # Get org.id
        
        print(f"✅ Created organization: {org.name} (ID: {org.id})")
        
        # Create admin user
        admin_user = User(
            username="admin",
            email="admin@example.com",
            hashed_password=hash_password("Admin@123"),
            full_name="System Administrator",
            role=UserRole.ADMIN,
            organization_id=org.id,
            active=True,
            last_login=None
        )
        db.add(admin_user)
        db.flush()
        
        print(f"✅ Created admin user: {admin_user.username}")
        print(f"   Email: {admin_user.email}")
        print(f"   Password: Admin@123")
        print(f"   ⚠️  IMPORTANT: Change this password immediately!")
        
        # Create example security engineer
        security_eng = User(
            username="security.engineer",
            email="security@example.com",
            hashed_password=hash_password("SecEng@123"),
            full_name="Security Engineer",
            role=UserRole.SECURITY_ENGINEER,
            organization_id=org.id,
            active=True
        )
        db.add(security_eng)
        
        print(f"✅ Created security engineer: {security_eng.username}")
        
        # Create example auditor
        auditor = User(
            username="auditor",
            email="auditor@example.com",
            hashed_password=hash_password("Auditor@123"),
            full_name="Compliance Auditor",
            role=UserRole.AUDITOR,
            organization_id=org.id,
            active=True
        )
        db.add(auditor)
        
        print(f"✅ Created auditor: {auditor.username}")
        
        # Create example environment
        env = Environment(
            organization_id=org.id,
            name="Production OpenStack",
            type="production",
            description="Production OpenStack environment (Kolla-Ansible Yoga)",
            controller_host="controller.example.com",
            ssh_user="deployer",
            openstack_version="Yoga",
            deployment_method="kolla-ansible",
            compliance_standards=["CIS OpenStack Benchmark", "CIS Linux Benchmark"],
            scan_schedule="0 2 * * *",  # Daily at 2 AM
            active=True
        )
        db.add(env)
        
        print(f"✅ Created environment: {env.name}")
        
        db.commit()
    
    print("\n" + "="*60)
    print("✅ Database initialization complete!")
    print("="*60)
    print("\n📝 Default Credentials:")
    print("-"*60)
    print("Admin User:")
    print("  Username: admin")
    print("  Password: Admin@123")
    print("")
    print("Security Engineer:")
    print("  Username: security.engineer")
    print("  Password: SecEng@123")
    print("")
    print("Auditor:")
    print("  Username: auditor")
    print("  Password: Auditor@123")
    print("-"*60)
    print("\n⚠️  SECURITY WARNING:")
    print("Change all default passwords immediately!")
    print("="*60)


if __name__ == "__main__":
    try:
        init_database()
    except Exception as e:
        print(f"\n❌ Error during initialization: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
