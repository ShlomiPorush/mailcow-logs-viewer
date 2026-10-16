"""Upgrade steps that repair what earlier bounce counting and rule editing left
in the database. Each runs on seeded rows in a schema of its own."""
import importlib.util
import pathlib
import uuid
from contextlib import contextmanager
from datetime import datetime

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from app.models import Base, PostfixLog, SystemSetting


def _revision(suffix):
    versions = pathlib.Path(__file__).resolve().parent.parent / "alembic" / "versions"
    matches = sorted(versions.glob(f"*_{suffix}.py"))
    assert matches, f"upgrade step {suffix} is missing"
    spec = importlib.util.spec_from_file_location(suffix, matches[0])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@contextmanager
def _schema(*tables):
    from app.database import engine
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        pytest.skip("PostgreSQL not available")
    schema = "upgrade_test_" + uuid.uuid4().hex
    with engine.begin() as conn:
        conn.execute(text(f"CREATE SCHEMA {schema}"))
    isolated = create_engine(engine.url, connect_args={"options": f"-csearch_path={schema}"})
    try:
        Base.metadata.create_all(isolated, tables=[t.__table__ for t in tables])
        yield isolated
    finally:
        isolated.dispose()
        with engine.begin() as conn:
            conn.execute(text(f"DROP SCHEMA {schema} CASCADE"))


def _upgrade(isolated, revision):
    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    with isolated.begin() as conn:
        with Operations.context(MigrationContext.configure(conn)):
            revision.upgrade()


# -- 0016: bounce detection's mark starts at the lines already stored ---------

def _mark(isolated):
    with isolated.connect() as conn:
        return conn.execute(text(
            "SELECT value FROM system_settings WHERE key = 'suppression_bounce_log_watermark'")).scalar()


def test_bounce_mark_starts_at_the_newest_stored_line():
    import app.scheduler as sch
    revision = _revision("bounce_log_watermark")
    assert revision.KEY == sch.BOUNCE_WATERMARK_KEY
    with _schema(PostfixLog, SystemSetting) as isolated:
        _upgrade(isolated, revision)
        assert _mark(isolated) == "0"   # no lines yet

    with _schema(PostfixLog, SystemSetting) as isolated:
        now = datetime.utcnow()
        with Session(isolated) as db:
            for n in range(3):
                db.add(PostfixLog(time=now, created_at=now, program="postfix/smtp", message=f"line {n}",
                                  queue_id=f"Q{n}", recipient="user@example.com", status="deferred", dsn="4.4.1"))
            db.commit()
            newest = max(row.id for row in db.query(PostfixLog).all())
        _upgrade(isolated, revision)
        assert _mark(isolated) == str(newest)
        # Running it again keeps the mark detection has moved on since
        with isolated.begin() as conn:
            conn.execute(text("UPDATE system_settings SET value = '999999' "
                              "WHERE key = 'suppression_bounce_log_watermark'"))
        _upgrade(isolated, revision)
        assert _mark(isolated) == "999999"
