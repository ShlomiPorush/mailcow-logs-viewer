"""Database-backed exports load bounded batches and release interrupted sessions."""
import asyncio
import csv
import inspect
import io
import uuid
from datetime import datetime, timedelta

import anyio
import pytest
from fastapi import FastAPI
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import Session
from starlette.requests import ClientDisconnect, Request

from app.database import Base, engine, get_db
from app.models import PostfixLog, RspamdLog, NetfilterLog, MessageCorrelation, SpamSuppression
from app.routers import export, suppressions


@pytest.fixture
def isolated_engine():
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        pytest.skip("PostgreSQL not available")
    schema = "csv_stream_test_" + uuid.uuid4().hex
    with engine.begin() as conn:
        conn.execute(text(f"CREATE SCHEMA {schema}"))
    isolated = create_engine(engine.url, connect_args={"options": f"-csearch_path={schema}"})
    try:
        Base.metadata.create_all(isolated, tables=[model.__table__ for model in
            (PostfixLog, RspamdLog, NetfilterLog, MessageCorrelation, SpamSuppression)])
        yield isolated
    finally:
        isolated.dispose()
        with engine.begin() as conn:
            conn.execute(text(f"DROP SCHEMA {schema} CASCADE"))
            assert conn.execute(text("SELECT count(*) FROM information_schema.schemata WHERE schema_name=:name"),
                                {"name": schema}).scalar() == 0


@pytest.mark.parametrize("model,endpoint", [
    (PostfixLog, export.export_postfix_csv), (RspamdLog, export.export_rspamd_csv),
    (NetfilterLog, export.export_netfilter_csv), (MessageCorrelation, export.export_messages_csv),
    (SpamSuppression, suppressions.export_suppressions),
])
def test_exports_fetch_bounded_batches(isolated_engine, model, endpoint):
    count = 1100
    now = datetime(2026, 1, 1)
    with Session(isolated_engine) as db:
        if model is MessageCorrelation:
            rspamd = [RspamdLog(time=now, score=i) for i in range(count)]
            db.add_all(rspamd)
            db.flush()
            rows = [MessageCorrelation(correlation_key=f"stream-{i}", subject=str(i),
                    first_seen=now, last_seen=now + timedelta(seconds=i),
                    rspamd_log_id=rspamd[i].id if i % 2 else None) for i in range(count)]
        elif model is SpamSuppression:
            rows = [SpamSuppression(email=f"user-{i}@example.com", reason="manual", notes=str(i),
                    created_at=now + timedelta(seconds=i)) for i in range(count)]
        else:
            field = "subject" if model is RspamdLog else "message"
            rows = [model(time=now + timedelta(seconds=i), **{field: str(i)}) for i in range(count)]
        db.add_all(rows)
        db.commit()
    loaded = []
    cursors = []
    def load(row, context):
        loaded.append(row.id)
    def capture(conn, cursor, statement, parameters, context, executemany):
        cursors.append(cursor.name)
    event.listen(model, "load", load)
    event.listen(isolated_engine, "before_cursor_execute", capture)
    try:
        with Session(isolated_engine) as db:
            kwargs = {name: None for name in inspect.signature(endpoint).parameters if name != "db"}
            if "request" in kwargs:
                kwargs["request"] = Request({"type": "http", "method": "GET"})
            response = endpoint(db=db, **kwargs)
            assert 0 < len(loaded) <= 500, "export loaded all source records before streaming"
            async def consume():
                return b"".join([chunk async for chunk in response.body_iterator])
            records = list(csv.DictReader(io.StringIO(asyncio.run(consume()).decode("utf-8-sig"))))
            assert len(records) == count
            assert len(loaded) == len(set(loaded)) == count
            field = "notes" if model is SpamSuppression else "Subject" if model in (RspamdLog, MessageCorrelation) else "Message"
            order = list(range(count)) if model is SpamSuppression else list(reversed(range(count)))
            assert [int(row[field]) for row in records] == order
            if model is MessageCorrelation:
                for row in records:
                    index = int(row["Subject"])
                    assert row["Spam Score"] == (str(float(index)) if index % 2 else "")
            assert len(cursors) == 1
            assert all(cursors), "export must use a PostgreSQL server-side cursor"
    finally:
        event.remove(model, "load", load)
        event.remove(isolated_engine, "before_cursor_execute", capture)
    assert isolated_engine.pool.checkedout() == 0


@pytest.mark.parametrize("spec", ["2.3", "2.4"])
def test_disconnect_closes_database_session(isolated_engine, spec):
    with Session(isolated_engine) as db:
        db.add_all([PostfixLog(time=datetime(2026, 1, 1), message="Example") for _ in range(1100)])
        db.commit()
    closed = []
    app = FastAPI()
    app.include_router(export.router)
    def session():
        db = Session(isolated_engine)
        try:
            yield db
        finally:
            cursors = db.execute(text("SELECT count(*) FROM pg_cursors WHERE name LIKE 'c_%'")).scalar()
            db.close()
            closed.append(cursors)
    app.dependency_overrides[get_db] = session
    async def run():
        disconnect = anyio.Event()
        async def receive():
            await disconnect.wait()
            return {"type": "http.disconnect"}
        async def send(message):
            if message["type"] == "http.response.body" and message.get("body"):
                if spec == "2.4":
                    raise OSError("fixture disconnected client")
                disconnect.set()
                await anyio.sleep_forever()
        scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": spec},
                 "method": "GET", "path": "/export/postfix/csv", "raw_path": b"/export/postfix/csv",
                 "query_string": b"", "headers": [], "scheme": "http", "http_version": "1.1",
                 "server": ("testserver", 80), "client": ("127.0.0.1", 12345), "root_path": ""}
        if spec == "2.4":
            with pytest.raises(ClientDisconnect):
                await app(scope, receive, send)
        else:
            await app(scope, receive, send)
    asyncio.run(run())
    assert closed == [0], "export cursor must close before the dependency closes its session"
    assert isolated_engine.pool.checkedout() == 0
