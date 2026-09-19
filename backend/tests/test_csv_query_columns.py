"""CSV projections preserve output without fetching unused payloads or lazy columns."""
import csv
import io
import uuid
from datetime import datetime

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import Session

from app.database import Base, engine, get_db
from app.config import settings
from app.models import PostfixLog, RspamdLog, NetfilterLog, MessageCorrelation, SpamSuppression
from app.routers import export, suppressions


@pytest.mark.parametrize("path,column,expected,queries,field_count", [
    ("/export/postfix/csv", "Message", "Example", 1, 12),
    ("/export/rspamd/csv", "Subject", "Example", 1, 15),
    ("/export/netfilter/csv", "Message", "Example", 1, 9),
    ("/export/messages/csv", "Subject", "Example", 1, 13),
    ("/suppressions/export", "notes", "'=1+1", 1, 12),
])
def test_csv_selects_only_export_columns(monkeypatch, path, column, expected, queries, field_count):
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        pytest.skip("PostgreSQL not available")
    schema = "csv_columns_test_" + uuid.uuid4().hex
    with engine.begin() as conn:
        conn.execute(text(f"CREATE SCHEMA {schema}"))
    isolated = create_engine(engine.url, connect_args={"options": f"-csearch_path={schema}"})
    models = (PostfixLog, RspamdLog, NetfilterLog, MessageCorrelation, SpamSuppression)
    try:
        Base.metadata.create_all(isolated, tables=[model.__table__ for model in models])
        with Session(isolated) as db:
            for i in range(2):
                stamp = datetime(2026, 1, i + 1)
                rspamd = RspamdLog(time=stamp, subject="Example", score=-1.5, ip="192.0.2.10",
                    recipients_smtp=["recipient@example.com"], symbols={"EXAMPLE": {}},
                    raw_data={"unused": "x" * 10000})
                db.add(rspamd)
                db.flush()
                db.add_all([
                    PostfixLog(time=stamp, message="Example", sender="sender@example.com",
                               raw_data={"unused": "x" * 10000}),
                    NetfilterLog(time=stamp, message="Example", raw_data={"unused": "x" * 10000}),
                    MessageCorrelation(correlation_key=f"csv-columns-{i}", first_seen=stamp, last_seen=stamp,
                        subject="Example", rspamd_log_id=rspamd.id if i == 0 else None,
                        postfix_log_ids=list(range(1000))),
                    SpamSuppression(email=f"user-{i}@example.com", type="email", reason="manual", notes="=1+1",
                                    last_bounce_message="x" * 10000),
                ])
            db.commit()
        app = FastAPI()
        app.include_router(export.router)
        app.include_router(suppressions.router)
        def session():
            with Session(isolated) as db:
                yield db
        app.dependency_overrides[get_db] = session
        statements = []
        def capture(conn, cursor, statement, parameters, context, executemany):
            statements.append(statement)
        event.listen(isolated, "before_cursor_execute", capture)
        try:
            with TestClient(app) as client:
                response = client.get(path)
                assert response.status_code == 200
                assert response.content.startswith(b"\xef\xbb\xbf")
                records = list(csv.DictReader(io.StringIO(response.content.decode("utf-8-sig"))))
                assert len(records) == 2
                assert all(len(row) == field_count and row[column] == expected for row in records)
                if path == "/export/messages/csv":
                    assert [row["Spam Score"] for row in records] == ["", "-1.5"]
                if path == "/suppressions/export":
                    assert all(row["_csv_escape_v1"] == "notes" for row in records)
                assert len(statements) == queries, "export caused extra deferred-column queries"
                for sql in statements:
                    assert "raw_data" not in sql
                    assert "postfix_log_ids" not in sql
                    assert "last_bounce_message" not in sql
                if path == "/export/messages/csv":
                    filtered = client.get(path, params={"ip": "192.0.2.10"})
                    rows = list(csv.DictReader(io.StringIO(filtered.content.decode("utf-8-sig"))))
                    assert len(rows) == 1 and rows[0]["Spam Score"] == "-1.5"
                monkeypatch.setattr(settings._inner, "csv_export_limit", 1)
                limited = client.get(path)
                rows = list(csv.DictReader(io.StringIO(limited.content.decode("utf-8-sig"))))
                assert len(rows) == (2 if path == "/suppressions/export" else 1)
        finally:
            event.remove(isolated, "before_cursor_execute", capture)
    finally:
        isolated.dispose()
        with engine.begin() as conn:
            conn.execute(text(f"DROP SCHEMA {schema} CASCADE"))
            assert conn.execute(text("SELECT count(*) FROM information_schema.schemata WHERE schema_name=:name"),
                                {"name": schema}).scalar() == 0
