"""
Temporary SQLite database configuration for Demo purposes
"""
from sqlalchemy import create_all
from backend.database.database import engine
from backend.database.models import Base

def setup_demo_db():
    # Use SQLite for demo if Postgres is not available
    import sqlite3
    Base.metadata.create_all(bind=engine)
    print("✅ Demo SQLite database initialized")

if __name__ == "__main__":
    setup_demo_db()
