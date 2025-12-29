"""
Enterprise Compliance Platform - FastAPI Backend
Main application entry point
"""

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from contextlib import asynccontextmanager
import time
import logging
from typing import Dict

from backend.database.database import create_tables, check_database_health
from backend.api.v1 import auth, scans, findings, exceptions, reports, users, settings
from backend.auth.dependencies import get_current_user

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# Lifespan context manager for startup/shutdown events
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle startup and shutdown events"""
    # Startup
    logger.info("🚀 Starting Enterprise Compliance Platform...")
    
    # Create database tables
    try:
        create_tables()
        logger.info("✅ Database tables initialized")
    except Exception as e:
        logger.error(f"❌ Failed to initialize database: {e}")
        raise
    
    # Check database health
    if check_database_health():
        logger.info("✅ Database connection healthy")
    else:
        logger.error("❌ Database connection failed")
        raise Exception("Database health check failed")
    
    logger.info("✅ Application startup complete")
    
    yield
    
    # Shutdown
    logger.info("🛑 Shutting down Enterprise Compliance Platform...")


# Create FastAPI application
app = FastAPI(
    title="Enterprise Compliance Platform API",
    description="""
    **Enterprise-Grade Compliance Management System**
    
    This API provides comprehensive compliance management for OpenStack cloud environments.
    
    ## Features
    
    * 🔍 **Automated Scanning** - Schedule and run CIS Benchmark scans
    * 📊 **Real-time Dashboards** - Monitor compliance status
    * ⚠️ **Finding Management** - Track and remediate violations
    * 📝 **Exception Workflow** - Request and approve compliance exceptions
    * 🤖 **Auto-Remediation** - Automated fix deployment
    * 📈 **Trend Analysis** - Historical compliance tracking
    * 🔐 **RBAC** - Role-based access control
    * 📋 **Audit Trail** - Complete action logging
    
    ## Authentication
    
    Most endpoints require JWT authentication. Use `/api/v1/auth/login` to obtain a token.
    
    """,
    version="1.0.0",
    contact={
        "name": "Security Team",
        "email": "security@example.com"
    },
    license_info={
        "name": "MIT",
        "url": "https://opensource.org/licenses/MIT"
    },
    lifespan=lifespan,
    docs_url=None,  # We'll customize this
    redoc_url=None
)


# ============================================
# Middleware Configuration
# ============================================

# CORS - Configure for production
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",  # React dev server
        "http://localhost:5173",  # Vite dev server
        # Add production URLs here
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# GZip compression
app.add_middleware(GZipMiddleware, minimum_size=1000)


# Request timing middleware
@app.middleware("http")
async def add_process_time_header(request, call_next):
    """Add X-Process-Time header to responses"""
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(f"{process_time:.4f}")
    return response


# ============================================
# API Routes
# ============================================

# Include API routers
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(scans.router, prefix="/api/v1/scans", tags=["Scans"])
app.include_router(findings.router, prefix="/api/v1/findings", tags=["Findings"])
app.include_router(exceptions.router, prefix="/api/v1/exceptions", tags=["Exceptions"])
app.include_router(reports.router, prefix="/api/v1/reports", tags=["Reports"])
app.include_router(users.router, prefix="/api/v1/users", tags=["Users"])
app.include_router(settings.router, prefix="/api/v1/settings", tags=["Settings"])


# ============================================
# Root & Health Endpoints
# ============================================

@app.get("/", tags=["Root"])
async def root() -> Dict:
    """API root endpoint"""
    return {
        "name": "Enterprise Compliance Platform API",
        "version": "1.0.0",
        "status": "operational",
        "docs": "/docs",
        "health": "/health"
    }


@app.get("/health", tags=["Health"])
async def health_check() -> Dict:
    """Health check endpoint for monitoring"""
    db_healthy = check_database_health()
    
    return {
        "status": "healthy" if db_healthy else "unhealthy",
        "database": "connected" if db_healthy else "disconnected",
        "timestamp": time.time()
    }


@app.get("/metrics", tags=["Monitoring"])
async def metrics() -> Dict:
    """Prometheus-compatible metrics endpoint"""
    # TODO: Implement proper Prometheus metrics
    return {
        "api_requests_total": 0,
        "api_request_duration_seconds": 0,
        "database_connections_active": 0
    }


# ============================================
# Custom OpenAPI Documentation
# ============================================

@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    """Custom Swagger UI"""
    return get_swagger_ui_html(
        openapi_url="/openapi.json",
        title=f"{app.title} - Swagger UI",
        swagger_favicon_url="/static/favicon.ico"
    )


@app.get("/openapi.json", include_in_schema=False)
async def get_open_api_endpoint():
    """Custom OpenAPI schema"""
    return JSONResponse(
        get_openapi(
            title=app.title,
            version=app.version,
            description=app.description,
            routes=app.routes,
        )
    )


# ============================================
# Error Handlers
# ============================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Custom HTTP exception handler"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "timestamp": time.time()
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """General exception handler"""
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "status_code": 500,
            "timestamp": time.time()
        }
    )


# ============================================
# Main Entry Point
# ============================================

if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "backend.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,  # Disable in production
        log_level="info",
        access_log=True
    )
