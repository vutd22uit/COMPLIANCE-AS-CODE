"""
Database connection and session management
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import QueuePool
from contextlib import contextmanager
from typing import Generator
import os

from .models import Base

# Database URL from environment variables
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://compliance:compliance_pass@localhost:5432/compliance_db"
)

# Create engine with connection pooling
is_sqlite = DATABASE_URL.startswith("sqlite")

engine_args = {
    "echo": os.getenv("SQL_ECHO", "false").lower() == "true"
}

if is_sqlite:
    engine_args["connect_args"] = {"check_same_thread": False}
else:
    engine_args.update({
        "poolclass": QueuePool,
        "pool_size": 20,
        "max_overflow": 40,
        "pool_pre_ping": True,
    })

engine = create_engine(DATABASE_URL, **engine_args)

# Session factory
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)


def create_tables():
    """Create all database tables"""
    Base.metadata.create_all(bind=engine)


def drop_tables():
    """Drop all database tables (use with caution!)"""
    Base.metadata.drop_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    """
    Dependency function for FastAPI to get database session
    
    Usage:
        @app.get("/items")
        def read_items(db: Session = Depends(get_db)):
            return db.query(Item).all()
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def get_db_context() -> Generator[Session, None, None]:
    """
    Context manager for database session
    
    Usage:
        with get_db_context() as db:
            user = db.query(User).first()
    """
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


# Health check function
def check_database_health() -> bool:
    """Check if database connection is healthy"""
    from sqlalchemy import text
    try:
        with get_db_context() as db:
            db.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
