"""Import duplicates must be skipped even before the final commit."""
import csv
import io
import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.database import Base, engine
from app.models import SpamSuppression
from app.routers import suppressions


@pytest.mark.parametrize("header", [True, False])
@pytest.mark.parametrize("entry_type", ["email", "domain"])
def test_import_keeps_first_new_row_and_skips_normalized_duplicates(monkeypatch, header, entry_type):
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        pytest.skip("PostgreSQL not available")
    schema = "suppression_import_" + uuid.uuid4().hex
    with engine.begin() as conn:
        conn.execute(text(f"CREATE SCHEMA {schema}"))
    isolated = create_engine(engine.url, connect_args={"options": f"-csearch_path={schema}"})
    sessions = sessionmaker(bind=isolated, autoflush=False)
    address = "user@example.test" if entry_type == "email" else "example.test"
    try:
        Base.metadata.create_all(isolated, tables=[SpamSuppression.__table__])
        with sessions() as db:
            db.add(SpamSuppression(email="existing@example.test", active=False, reason="manual", source="manual", notes="unchanged"))
            db.commit()
        monkeypatch.setattr(suppressions, "SessionLocal", sessions)
        content = io.StringIO()
        writer = csv.writer(content)
        if header:
            writer.writerow(["email", "type", "reason", "notes"])
        writer.writerows([
            ["  " + address.upper() + "  ", entry_type, "manual", "first, quoted note"],
            [address, entry_type, "hard_bounce", "later note"],
            [address.upper(), entry_type, "soft_bounce", "third note"],
            ["other@example.test", "email", "manual", "other note"],
            ["EXISTING@example.test", "email", "manual", "replacement"],
            ["existing@example.test", "email", "manual", "replacement again"],
        ])
        app = FastAPI()
        app.include_router(suppressions.router, prefix="/api")
        client = TestClient(app, raise_server_exceptions=False)
        payload = content.getvalue().encode("utf-8-sig")
        response = client.post("/api/suppressions/import", files={"file": ("duplicates.csv", payload)})
        assert response.status_code == 200, response.text
        assert response.json() == {"imported": 2, "skipped": 4, "errors": []}
        with sessions() as db:
            rows = {row.email: row for row in db.query(SpamSuppression).all()}
            assert len(rows) == 3
            assert rows[address].notes == "first, quoted note"
            assert rows[address].reason == "manual"
            assert rows[address].type == entry_type
            assert rows[address].source == "import"
            assert rows["existing@example.test"].active is False
            assert rows["existing@example.test"].notes == "unchanged"
        repeated = client.post("/api/suppressions/import", files={"file": ("duplicates.csv", payload)})
        assert repeated.json() == {"imported": 0, "skipped": 6, "errors": []}
    finally:
        isolated.dispose()
        with engine.begin() as conn:
            conn.execute(text(f"DROP SCHEMA {schema} CASCADE"))
