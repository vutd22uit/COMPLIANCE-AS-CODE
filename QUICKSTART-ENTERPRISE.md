# 🚀 Quick Test Guide - Enterprise Edition

## Prerequisites Check

```bash
# Check Docker
docker --version
docker-compose --version

# Check Python
python3 --version  # Should be 3.11+

# Check current directory
pwd  # Should be .../COMPLIANCE-AS-CODE
```

---

## 🏃 Quick Start (5 minutes)

### Step 1: Install Python Dependencies

```bash
# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On macOS/Linux

# Install dependencies
pip install -r requirements.txt
```

### Step 2: Start Database (PostgreSQL + Redis)

```bash
# Start only database services first
docker-compose -f docker-compose.enterprise.yml up -d postgres redis

# Wait 10 seconds for databases to be ready
sleep 10

# Check if running
docker ps
```

Expected output:
```
CONTAINER ID   IMAGE                  STATUS
xxxxxxxxxxxx   postgres:15-alpine     Up 10 seconds (healthy)
xxxxxxxxxxxx   redis:7-alpine         Up 10 seconds (healthy)
```

### Step 3: Initialize Database

```bash
# Create tables and default users
python3 backend/database/init_db.py
```

Expected output:
```
🔧 Initializing database...
📋 Creating database tables...
✅ Tables created successfully

👤 Creating default admin user...
✅ Created organization: Default Organization (ID: 1)
✅ Created admin user: admin
   Email: admin@example.com
   Password: Admin@123
   ⚠️  IMPORTANT: Change this password immediately!
✅ Created security engineer: security.engineer
✅ Created auditor: auditor
✅ Created environment: Production OpenStack

✅ Database initialization complete!
```

### Step 4: Start Backend API

```bash
# Run FastAPI backend
uvicorn backend.main:app --reload --port 8000
```

Expected output:
```
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
INFO:     Started reloader process [xxxxx]
🚀 Starting Enterprise Compliance Platform...
✅ Database tables initialized
✅ Database connection healthy
✅ Application startup complete
INFO:     Application startup complete.
```

---

## 🧪 Test the API

### Open API Documentation

Open your browser: **http://localhost:8000/docs**

You should see **Swagger UI** with all API endpoints!

### Test Authentication (using curl)

```bash
# 1. Login as admin
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "Admin@123"
  }' | jq
```

**Expected Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600,
  "user": {
    "id": 1,
    "username": "admin",
    "email": "admin@example.com",
    "role": "admin",
    "organization_id": 1
  }
}
```

### Save your token:

```bash
# Copy the access_token from the response above
export TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### Test Protected Endpoint

```bash
# Get current user info
curl -X GET http://localhost:8000/api/v1/auth/me \
  -H "Authorization: Bearer $TOKEN" | jq
```

### Create a Scan Job

```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "environment_id": 1,
    "scan_type": "openstack",
    "scheduled_time": null
  }' | jq
```

### List All Scans

```bash
curl -X GET http://localhost:8000/api/v1/scans \
  -H "Authorization: Bearer $TOKEN" | jq
```

---

## 🎨 Using Swagger UI (Easier!)

### 1. Open Swagger UI
Go to: **http://localhost:8000/docs**

### 2. Authenticate
- Click **"Authorize"** button (top right)
- Login endpoint: POST `/api/v1/auth/login`
- Click "Try it out"
- Enter:
  ```json
  {
    "username": "admin",
    "password": "Admin@123"
  }
  ```
- Click "Execute"
- Copy the `access_token` from response
- Click "Authorize" again
- Paste token in "Value" field
- Click "Authorize" then "Close"

### 3. Test Endpoints
Now you can test any endpoint directly in the browser!

---

## 🐳 Full Stack Deployment (Optional)

If you want to run everything with Docker Compose:

```bash
# Build and start all services
docker-compose -f docker-compose.enterprise.yml up -d --build

# View logs
docker-compose -f docker-compose.enterprise.yml logs -f backend

# Initialize database (one time only)
docker-compose -f docker-compose.enterprise.yml exec backend \
  python backend/database/init_db.py

# Access services:
# - API: http://localhost:8000
# - API Docs: http://localhost:8000/docs
# - Grafana: http://localhost:3000
# - Prometheus: http://localhost:9091
```

---

## 🛑 Stop Services

### If running locally:
```bash
# Stop FastAPI (Ctrl+C in terminal)
# Stop Docker containers
docker-compose -f docker-compose.enterprise.yml down
```

### If using full Docker Compose:
```bash
docker-compose -f docker-compose.enterprise.yml down

# To remove volumes (delete database):
docker-compose -f docker-compose.enterprise.yml down -v
```

---

## ✅ Verification Checklist

- [ ] PostgreSQL running (port 5432)
- [ ] Redis running (port 6379)
- [ ] Backend API running (port 8000)
- [ ] Can access http://localhost:8000/docs
- [ ] Can login with admin/Admin@123
- [ ] Can create scan job
- [ ] Database has default users

---

## 🐛 Troubleshooting

### "Connection refused" error

```bash
# Check if services are running
docker ps

# Check logs
docker logs compliance_postgres
docker logs compliance_redis
```

### "ModuleNotFoundError"

```bash
# Make sure you installed requirements
pip install -r requirements.txt

# Set Python path
export PYTHONPATH=/Users/vutruongdoan/BENMARK/COMPLIANCE-AS-CODE
```

### "Database connection failed"

```bash
# Check PostgreSQL is running
docker exec compliance_postgres pg_isready

# Check connection string in environment
echo $DATABASE_URL

# Try manual connection
docker exec -it compliance_postgres psql -U compliance -d compliance_db
```

### "Port already in use"

```bash
# Find what's using port 8000
lsof -i :8000

# Kill process or use different port
uvicorn backend.main:app --reload --port 8001
```

---

## 📚 Next Steps

1. **Explore API Endpoints** - http://localhost:8000/docs
2. **Read Enterprise README** - [ENTERPRISE-README.md](./ENTERPRISE-README.md)
3. **Check Implementation Plan** - [.agent/workflows/enterprise-upgrade-plan.md](./.agent/workflows/enterprise-upgrade-plan.md)
4. **View Upgrade Summary** - [ENTERPRISE-UPGRADE-SUMMARY.md](./ENTERPRISE-UPGRADE-SUMMARY.md)

---

## 🎯 What You've Built

You now have:
- ✅ Production-ready REST API
- ✅ PostgreSQL database with proper schema
- ✅ JWT authentication system
- ✅ RBAC with 4 user roles
- ✅ Audit logging
- ✅ OpenAPI documentation
- ✅ Docker deployment

**Ready to demo in job interviews!** 🚀

---

**Need help?**  
Check the logs:
```bash
# Backend logs
tail -f logs/backend.log

# Docker logs
docker-compose -f docker-compose.enterprise.yml logs -f
```
