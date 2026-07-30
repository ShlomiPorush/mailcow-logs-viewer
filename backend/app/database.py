"""
Database connection and session management
"""
from sqlalchemy import create_engine, event, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool
from contextlib import contextmanager
import logging

from .config import settings

logger = logging.getLogger(__name__)

# Create SQLAlchemy engine
engine_kwargs = {
    "echo": settings.debug,
    "pool_pre_ping": True,
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


@event.listens_for(engine, "connect")
def set_session_timezone(dbapi_conn, connection_record):
    """Pin every DB session to UTC (issue #19).

    The log tables use TIMESTAMP WITHOUT TIME ZONE columns while ingest binds
    timezone-aware UTC datetimes. PostgreSQL converts such values to the
    SESSION timezone before dropping the offset - so when the postgres
    container runs with e.g. TZ=Europe/Berlin (baked in at initdb), UTC 07:15
    is stored as 08:15, later serialized as "08:15Z", and the browser adds
    the local offset a second time. Displayed times end up ahead by exactly
    the UTC offset (1h CET, 2h CEST). Forcing the session to UTC makes the
    conversion an identity regardless of how the DB container is configured.
    """
    cursor = dbapi_conn.cursor()
    cursor.execute("SET TIME ZONE 'UTC'")
    cursor.close()


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