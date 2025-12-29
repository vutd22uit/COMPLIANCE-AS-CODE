# 🚀 Enterprise Compliance Platform - Quick Start Guide

## Overview

This is the **Enterprise-Grade** version of the Compliance-as-Code framework, designed for production use in **Cloud Security Engineer** roles at cloud providers, banks, and large enterprises.

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                   ENTERPRISE PLATFORM                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Web Dashboard (React) ─► REST API (FastAPI) ─► PostgreSQL     │
│                                ↓                                 │
│                          Celery Workers                          │
│                                ↓                                 │
│                    InSpec/OPA/Ansible Scans                     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## ✨ Features

### Core Capabilities
- ✅ **REST API** - FastAPI backend with OpenAPI documentation
- ✅ **Database** - PostgreSQL for persistent storage
- ✅ **Authentication** - JWT-based auth with RBAC
- ✅ **Task Queue** - Celery + Redis for async scan execution
- ✅ **Real-time Dashboard** - Grafana + Prometheus monitoring
- ✅ **Multi-Tenant** - Organization-based isolation
- ✅ **Audit Logging** - Complete action trail
- ✅ **Exception Workflow** - Request/approve compliance exceptions
- ✅ **Auto-Remediation** - Ansible-based fix automation

### Enterprise Features
- 🔐 **Role-Based Access Control (RBAC)**
  - Admin - Full access
  - Security Engineer - Operational access
  - Auditor - Read-only access
  - Customer - Limited view

- 📊 **Advanced Reporting**
  - PDF/Excel exports
  - Trend analysis
  - Executive summaries

- 🔔 **Integrations**
  - Jira ticket creation
  - Slack notifications
  - Webhook support

---

## 🚀 Quick Start (Development)

### Prerequisites
- Docker & Docker Compose
- Python 3.11+
- Git

### 1. Clone & Setup

```bash
cd /Users/vutruongdoan/BENMARK/COMPLIANCE-AS-CODE

# Start the entire stack
docker-compose -f docker-compose.enterprise.yml up -d
```

### 2. Initialize Database

```bash
# Run database migrations (first time only)
python backend/database/init_db.py
```

### 3. Access Services

| Service | URL | Credentials |
|---------|-----|-------------|
| **API Docs** | http://localhost:8000/docs | - |
| **Backend API** | http://localhost:8000 | - |
| **Grafana** | http://localhost:3000 | admin / openstack-cis-2024 |
| **Prometheus** | http://localhost:9091 | - |

### 4. Default Login

```bash
# Default admin account (created by init_db.py)
Username: admin
Password: Admin@123
```

⚠️ **Change the default password immediately!**

---

## 📖 API Usage Examples

### 1. Login

```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "Admin@123"
  }'
```

**Response:**
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
    "role": "admin"
  }
}
```

### 2. Create Scan Job

```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "environment_id": 1,
    "scan_type": "openstack",
    "scheduled_time": null
  }'
```

### 3. List Findings

```bash
curl -X GET "http://localhost:8000/api/v1/findings?severity=critical&status=open" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### 4. Request Exception

```bash
curl -X POST http://localhost:8000/api/v1/exceptions \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "finding_id": 123,
    "reason": "Legacy system - upgrade planned for Q2 2025",
    "business_justification": "Critical business application",
    "expiry_date": "2025-06-30T00:00:00Z"
  }'
```

---

## 🗂️ Project Structure

```
COMPLIANCE-AS-CODE/
├── backend/                      # NEW: Enterprise Backend
│   ├── main.py                   # FastAPI application
│   ├── api/v1/                   # API endpoints
│   │   ├── auth.py              # Authentication
│   │   ├── scans.py             # Scan management
│   │   ├── findings.py          # Findings CRUD
│   │   ├── exceptions.py        # Exception workflow
│   │   └── reports.py           # Report generation
│   ├── database/
│   │   ├── models.py            # SQLAlchemy models
│   │   ├── database.py          # DB connection
│   │   └── migrations/          # Alembic migrations
│   ├── auth/
│   │   ├── jwt_handler.py       # JWT tokens
│   │   ├── rbac.py              # RBAC system
│   │   └── dependencies.py      # FastAPI deps
│   ├── workers/                  # Celery tasks
│   ├── services/                 # Business logic
│   └── integrations/             # External APIs
│
├── tests/inspec/                 # Existing InSpec controls
├── policies/rego/                # Existing OPA policies
├── remediation/ansible/          # Existing Ansible playbooks
├── evidence/                     # Existing evidence system
│
├── docker-compose.enterprise.yml # Full stack deployment
├── Dockerfile.backend            # Backend image
└── requirements.txt              # Updated dependencies
```

---

## 🔐 Security Best Practices

### Production Deployment Checklist

- [ ] Change default database password
- [ ] Change default admin password
- [ ] Generate new JWT secret key: `openssl rand -hex 32`
- [ ] Enable HTTPS/TLS
- [ ] Configure firewall rules
- [ ] Set up database backups
- [ ] Enable audit logging
- [ ] Configure rate limiting
- [ ] Use secrets management (Vault, AWS Secrets Manager)
- [ ] Set up monitoring alerts

### Environment Variables (Production)

```bash
# Database
DATABASE_URL=postgresql://user:pass@host:5432/db

# JWT (generate with: openssl rand -hex 32)
JWT_SECRET_KEY=your-super-secret-key-32-characters

# Redis
REDIS_URL=redis://redis:6379/0

# Integrations
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK
JIRA_URL=https://your-company.atlassian.net
JIRA_API_TOKEN=your-jira-token
```

---

## 📊 Database Schema

### Key Tables

| Table | Purpose |
|-------|---------|
| `organizations` | Multi-tenant organizations |
| `users` | User accounts with RBAC |
| `environments` | OpenStack environments to scan |
| `scan_jobs` | Scan execution tracking |
| `findings` | Compliance violations |
| `exceptions` | Exception requests & approvals |
| `remediation_tasks` | Auto-remediation tracking |
| `audit_logs` | Complete action audit trail |
| `compliance_snapshots` | Daily/weekly snapshots |

---

## 🧪 Development

### Run Backend Locally (without Docker)

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
export DATABASE_URL="postgresql://compliance:compliance_pass@localhost:5432/compliance_db"
export REDIS_URL="redis://localhost:6379/0"
export JWT_SECRET_KEY="dev-secret-key-change-me"

# Run migrations
alembic upgrade head

# Start API server
uvicorn backend.main:app --reload --port 8000
```

### Run Celery Worker

```bash
celery -A backend.workers.celery_app worker --loglevel=info
```

### Run Tests

```bash
pytest tests/ -v
```

---

## 🎯 Use Cases for Cloud Security Engineer

### 1. Daily Compliance Scanning
```python
# Schedule daily scans via Celery
# Auto-trigger scans at 2 AM for all environments
# Results stored in PostgreSQL
# Alerts sent to Slack for CRITICAL findings
```

### 2. Exception Management
```python
# Security team requests exception
# Security Lead approves via API
# Auto-expires after set date
# Tracked in audit log
```

### 3. Executive Reporting
```python
# Generate monthly PDF report
# Trend analysis charts
# Top 10 violations
# Remediation progress
# Export to S3/email
```

### 4. Integration with Jira
```python
# Auto-create Jira tickets for CRITICAL/HIGH findings
# Sync remediation status
# Close tickets when findings resolved
```

---

## 📚 Additional Documentation

- [Architecture Details](./docs/architecture.md)
- [API Documentation](http://localhost:8000/docs) (when running)
- [Database Schema](./backend/database/SCHEMA.md)
- [RBAC Permissions](./backend/auth/RBAC.md)
- [Deployment Guide](./docs/deployment.md)

---

## 🤝 Contributing

This is a **capstone project** demonstrating enterprise-grade compliance automation.

For interview purposes, key highlights:
- ✅ Full-stack development (FastAPI + React)
- ✅ Database design (PostgreSQL with proper indexing)
- ✅ Authentication & Authorization (JWT + RBAC)
- ✅ Asynchronous task processing (Celery)
- ✅ Containerization (Docker + Docker Compose)
- ✅ CI/CD (GitHub Actions)
- ✅ Monitoring (Prometheus + Grafana)
- ✅ Security automation (InSpec + OPA + Ansible)

---

## 📞 Support

For questions about this project:
- **Email**: vutd22uit@student.example.com
- **GitHub**: https://github.com/vutd22uit/COMPLIANCE-AS-CODE

---

**Built for Cloud Security Engineer role at enterprise cloud providers** 🚀

Last Updated: 2025-12-29
