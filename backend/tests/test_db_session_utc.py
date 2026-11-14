"""Every database session works in UTC, whatever the database's own zone.

The columns are `timestamp without time zone` and the app binds aware UTC
times, which PostgreSQL turns into the session's zone before dropping the
offset (issue #19). The session was pinned with SET TIME ZONE in a connect
hook, but that SET ran inside the connection's first transaction: when the
pool rolled that transaction back, PostgreSQL undid the SET and the session
went back to the database's zone, so a suppression saved as 21:18Z was stored
as 00:18 with a PostgreSQL container on Asia/Jerusalem.
"""
import pytest
from sqlalchemy import text


@pytest.fixture
def database_in_jerusalem():
    from app.database import engine
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        pytest.skip("PostgreSQL not available")
    # Like a PostgreSQL container started with TZ=Asia/Jerusalem
    with engine.begin() as conn:
        conn.execute(text("ALTER ROLE CURRENT_USER SET timezone = 'Asia/Jerusalem'"))
    engine.dispose()
    try:
        yield engine
    finally:
        with engine.begin() as conn:
            conn.execute(text("ALTER ROLE CURRENT_USER RESET timezone"))
        engine.dispose()


def test_the_next_session_on_a_pooled_connection_is_still_utc(database_in_jerusalem):
    from app.database import SessionLocal
    # Closing a session hands its connection back to the pool with a rollback
    zones = []
    for _ in range(3):
        with SessionLocal() as db:
            zones.append(db.execute(text("SHOW timezone")).scalar())
    assert zones == ["UTC", "UTC", "UTC"]


def test_a_pooled_session_stores_utc(database_in_jerusalem):
    from app.database import SessionLocal
    for _ in range(3):
        with SessionLocal() as db:
            stored = db.execute(text(
                "SELECT CAST(CAST('2026-10-24T21:18:00+00:00' AS timestamptz) AS timestamp)")).scalar()
    assert stored.isoformat() == "2026-10-24T21:18:00"
