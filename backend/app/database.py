"""
Database connection and session management
"""
from sqlalchemy import create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool
from contextlib import contextmanager
import logging

from .config import settings

logger = logging.getLogger(__name__)

# Create SQLAlchemy engine
# Every session works in UTC (issue #19). The columns are TIMESTAMP WITHOUT
# TIME ZONE while the app binds timezone-aware UTC datetimes, and PostgreSQL
# converts such a value to the SESSION timezone before dropping the offset:
# with the postgres container on TZ=Europe/Berlin, UTC 07:15 was stored as
# 08:15. The zone is a startup option of the connection, so no transaction
# can undo it (a SET in a connect hook was rolled back with the connection's
# first transaction when the pool reset it, and the next session was back on
# the database's zone).
UTC_SESSION = {"options": "-c timezone=UTC"}

engine_kwargs = {
    "echo": settings.debug,
    "pool_pre_ping": True,
    "connect_args": UTC_SESSION,
}

if settings.debug:
    # NullPool closes connections immediately after use (no pooling)
    # It does NOT support pool_size / max_overflow parameters
    engine_kwargs["poolclass"] = NullPool
else:
    engine_kwargs["pool_size"] = 10
    engine_kwargs["max_overflow"] = 20

engine = create_engine(settings.database_url, **engine_kwargs)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for models
Base = declarative_base()


def get_db():
    """
    Dependency for FastAPI to get database session
    Usage: db: Session = Depends(get_db)
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def get_db_context():
    """
    Context manager for database session
    Usage:
        with get_db_context() as db:
            db.query(...)
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


def init_db():
    """
    Initialize database - create all tables
    Called on application startup
    """
    logger.info("Initializing database...")
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database initialized successfully")
        
        # Create indexes for better performance
        with get_db_context() as db:
            # Indexes are defined in models, but we can create custom ones here if needed
            pass
            
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise


def check_db_connection():
    """
    Check if database connection is working
    Returns True if connection is successful
    """
    try:
        with get_db_context() as db:
            db.execute(text("SELECT 1"))
        logger.info("Database connection check: OK")
        return True
    except Exception as e:
        logger.error(f"Database connection check failed: {e}")
        return False