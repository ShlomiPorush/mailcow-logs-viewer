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
