"""Domain overview database waits must not block concurrent requests."""
import asyncio
import threading
from contextlib import contextmanager
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import httpx
import pytest
from fastapi import FastAPI

from app.routers import dmarc


@pytest.mark.parametrize("stage", ["cache", "reports", "records"])
def test_overview_database_wait_keeps_http_responsive(monkeypatch, stage):
    started, release, finished = threading.Event(), threading.Event(), threading.Event()
    threads, closed = [], []
    db = Mock()
    report = SimpleNamespace(id=1, begin_date=int(datetime.now().timestamp()),
                             end_date=int(datetime.now().timestamp()),
                             org_name="Example", policy_published={"p": "reject"})
    record = SimpleNamespace(source_ip="192.0.2.1", count=4,
                             spf_result="fail", dkim_result="pass")

    def block():
        threads.append(threading.get_ident())
        started.set()
        release.wait(2)
        finished.set()

    def cached(*args):
        if stage == "cache":
            block()
        return {"dmarc": {"record": "v=DMARC1; p=reject"}}

    def query(model):
        if (stage == "reports" and model is dmarc.DMARCReport
                or stage == "records" and model is dmarc.DMARCRecord):
            block()
        result = Mock()
        result.filter.return_value.all.return_value = [report] if model is dmarc.DMARCReport else [record]
        return result

    db.query.side_effect = query

    @contextmanager
    def session():
        owner = threading.get_ident()
        try:
            yield db
        finally:
            assert threading.get_ident() == owner
            closed.append(owner)

    monkeypatch.setattr(dmarc, "SessionLocal", session, raising=False)
    monkeypatch.setattr(dmarc, "get_cached_dns_check", cached)
    dns = AsyncMock()
    monkeypatch.setattr(dmarc, "check_dmarc_record", dns)
    app = FastAPI()
    app.include_router(dmarc.router)
    app.dependency_overrides[dmarc.get_db] = lambda: db

    @app.get("/ping")
    async def ping():
        return {"ok": True}

    async def run():
        loop_thread = threading.get_ident()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as api:
            task = asyncio.create_task(api.get("/dmarc/domains/example.test/overview"))
            try:
                assert await asyncio.to_thread(started.wait, 3)
                assert not finished.is_set(), f"Overview {stage} blocked the request loop"
                assert (await api.get("/ping")).json() == {"ok": True}
                assert not finished.is_set()
            finally:
                release.set()
                response = await task
            assert response.status_code == 200, response.text
            data = response.json()
            assert data["totals"] == {"total_messages": 4, "dmarc_pass": 4,
                "dmarc_fail": 0, "dmarc_pass_pct": 100.0, "unique_ips": 1, "unique_reporters": 1}
            assert data["daily_stats"][0]["dkim_pass"] == 4
            assert data["daily_stats"][0]["spf_pass"] == 0
            assert data["dmarc_record"]["settings"]["policy"] == "reject"
        assert threads and all(t != loop_thread for t in threads + closed)
        assert len(closed) == 2

    asyncio.run(run())
    dns.assert_not_awaited()


@pytest.mark.parametrize("fail_at", [None, "dns", "reports"])
def test_live_dns_runs_after_cache_session_closes(monkeypatch, fail_at):
    db = Mock()
    db.query.return_value.filter.return_value.all.return_value = []
    active, closed = [], []

    @contextmanager
    def session():
        active.append(True)
        try:
            yield db
        finally:
            active.pop()
            closed.append(True)

    async def dns(domain):
        assert not active and closed == [True]
        assert domain == "empty.example.test"
        await asyncio.sleep(0)
        if fail_at == "dns":
            raise RuntimeError("DNS unavailable")
        return {"status": "error", "record": None}

    if fail_at == "reports":
        db.query.side_effect = RuntimeError("Database unavailable")
    monkeypatch.setattr(dmarc, "SessionLocal", session, raising=False)
    monkeypatch.setattr(dmarc, "get_cached_dns_check", lambda *args: None)
    monkeypatch.setattr(dmarc, "check_dmarc_record", dns)
    app = FastAPI()
    app.include_router(dmarc.router)
    app.dependency_overrides[dmarc.get_db] = lambda: db

    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test") as api:
            response = await api.get("/dmarc/domains/empty.example.test/overview")
        assert response.status_code == (500 if fail_at else 200), response.text
        if not fail_at:
            assert response.json() == {"domain": "empty.example.test", "policy": None,
                "daily_stats": [], "totals": {"total_messages": 0, "dmarc_pass": 0,
                "dmarc_fail": 0, "unique_ips": 0, "unique_reporters": 0},
                "dmarc_record": {"status": "error", "record": None}}
    asyncio.run(run())
    assert not active
    assert len(closed) == (1 if fail_at == "dns" else 2)
