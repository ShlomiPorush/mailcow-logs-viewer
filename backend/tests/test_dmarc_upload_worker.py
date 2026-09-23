"""Report processing owns its session off the request event loop."""
import asyncio
import threading
from contextlib import contextmanager
from datetime import datetime
from unittest.mock import Mock

import httpx
import pytest
from fastapi import FastAPI

from app.config import settings
from app.routers import dmarc
from app.services import tls_rpt_parser


@pytest.fixture
def upload(monkeypatch):
    monkeypatch.setattr(settings._inner, "dmarc_manual_upload_enabled", True)
    db = Mock()
    db.query.return_value.filter.return_value.first.return_value = None
    events = []
    active = []

    @contextmanager
    def session():
        owner = threading.get_ident()
        active.append(owner)
        events.append(("open", owner))
        try:
            yield db
        finally:
            assert threading.get_ident() == owner
            active.remove(owner)
            events.append(("close", owner))

    def parse_dmarc(*args):
        return {"report_id": "dmarc-example", "domain": "example.test", "org_name": "Example",
                "begin_date": 1700000000, "end_date": 1700086400,
                "records": [{"source_ip": "192.0.2.1", "count": 5}]}

    def parse_tls(*args):
        return {"report_id": "tls-example", "policy_domain": "example.test",
                "organization_name": "Example", "start_datetime": datetime(2026, 1, 1),
                "end_datetime": datetime(2026, 1, 2), "policies": [{}]}

    def add(row):
        row.id = 123

    db.add.side_effect = add
    monkeypatch.setattr(dmarc, "SessionLocal", session)
    monkeypatch.setattr(dmarc, "parse_dmarc_file", parse_dmarc)
    monkeypatch.setattr(tls_rpt_parser, "parse_tls_rpt_file", parse_tls)
    monkeypatch.setattr(dmarc, "enrich_dmarc_record", lambda row: row)
    monkeypatch.setattr(dmarc, "clear_dmarc_cache", Mock())
    app = FastAPI()
    app.include_router(dmarc.router)
    app.dependency_overrides[dmarc.get_db] = lambda: db

    @app.get("/ping")
    async def ping():
        return {"ok": True}

    return app, db, active, events


@pytest.mark.parametrize("tls,stage", [
    (tls, stage) for tls in (False, True)
    for stage in ("parse", "query", "flush", "commit", "cache")
] + [(False, "enrich")])
def test_processing_wait_keeps_other_requests_responsive(monkeypatch, upload, tls, stage):
    app, db, active, events = upload
    started, release, finished = threading.Event(), threading.Event(), threading.Event()
    threads = []

    def block():
        threads.append(threading.get_ident())
        started.set()
        release.wait(2)
        finished.set()

    target, name = (tls_rpt_parser, "parse_tls_rpt_file") if tls else (dmarc, "parse_dmarc_file")
    if stage == "parse":
        original = getattr(target, name)
        def parse(*args):
            block()
            return original(*args)
        monkeypatch.setattr(target, name, parse)
    elif stage == "enrich":
        def enrich(row):
            block()
            return row
        monkeypatch.setattr(dmarc, "enrich_dmarc_record", enrich)
    elif stage == "cache":
        dmarc.clear_dmarc_cache.side_effect = lambda db: block()
    else:
        operation = getattr(db, stage)
        def wait(*args):
            block()
            return operation.return_value
        operation.side_effect = wait

    async def run():
        loop_thread = threading.get_ident()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as api:
            task = asyncio.create_task(api.post("/dmarc/upload", files={
                "file": ("report.json" if tls else "report.xml.gz", b"data")}))
            try:
                assert await asyncio.to_thread(started.wait, 3)
                assert not finished.is_set(), f"Upload {stage} blocked the request loop"
                assert (await api.get("/ping")).json() == {"ok": True}
                assert not finished.is_set()
            finally:
                release.set()
                response = await task
        assert response.status_code == 200, response.text
        data = response.json()
        assert data["report_type"] == ("tls-rpt" if tls else "dmarc")
        assert data["status"] == "success" and data["report_id"] == 123
        assert data["policies_count" if tls else "records_count"] == 1
        assert [e[0] for e in events] == ["open", "close"]
        assert events[0][1] == events[1][1] == threads[0] != loop_thread
        assert not active
        db.commit.assert_called_once()
        dmarc.clear_dmarc_cache.assert_called_once_with(db)
    asyncio.run(run())


@pytest.mark.parametrize("tls", [False, True])
@pytest.mark.parametrize("outcome", ["invalid", "duplicate", "query", "commit"])
def test_rejection_duplicates_and_failures_close_session(monkeypatch, upload, tls, outcome):
    app, db, active, events = upload
    target, name = (tls_rpt_parser, "parse_tls_rpt_file") if tls else (dmarc, "parse_dmarc_file")
    if outcome == "invalid":
        monkeypatch.setattr(target, name, lambda *args: None)
    elif outcome == "duplicate":
        db.query.return_value.filter.return_value.first.return_value = Mock()
    else:
        getattr(db, outcome).side_effect = RuntimeError("Database unavailable")

    async def run():
        loop_thread = threading.get_ident()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test") as api:
            response = await api.post("/dmarc/upload", files={
                "file": ("report.json" if tls else "report.xml.gz", b"data")})
        assert response.status_code == {"invalid": 400, "duplicate": 200}.get(outcome, 500)
        if outcome == "duplicate":
            assert response.json()["status"] == "duplicate"
            db.add.assert_not_called()
            db.commit.assert_not_called()
        assert not active and [e[0] for e in events] == ["open", "close"]
        assert events[0][1] == events[1][1] != loop_thread
        if outcome in ("query", "commit"):
            db.rollback.assert_called_once()
        dmarc.clear_dmarc_cache.assert_not_called()
    asyncio.run(run())


def test_disabled_upload_does_not_open_session(monkeypatch, upload):
    app, db, active, events = upload
    monkeypatch.setattr(settings._inner, "dmarc_manual_upload_enabled", False)
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as api:
            response = await api.post("/dmarc/upload", files={"file": ("report.xml.gz", b"data")})
        assert response.status_code == 403
    asyncio.run(run())
    assert events == [] and not active
    db.query.assert_not_called()
