"""Database persistence and cleanup must not stall unrelated async requests."""
import asyncio
import threading
from types import SimpleNamespace

import pytest

from app import database
from app.routers import reporting, settings as settings_router


class OwnedSession:
    def __init__(self, sessions, blocking=None):
        self.owner = threading.get_ident()
        self.operations = []
        self.blocking = blocking
        sessions.append(self)

    def record(self, operation):
        self.operations.append((operation, threading.get_ident()))

    def commit(self):
        self.record("commit")

    def rollback(self):
        self.record("rollback")

    def close(self):
        self.record("close")
        if self.blocking:
            self.blocking()


async def run_with_heartbeat(operation, started, release):
    async def heartbeat():
        while not started.is_set():
            await asyncio.sleep(0.001)
        release.set()

    task = asyncio.create_task(heartbeat())
    try:
        return await operation
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("license_key,status", [("", 204), ("fake-license", 204), ("fake-license", 401), ("fake-license", 500), ("fake-license", None)])
def test_maxmind_persistence_keeps_loop_responsive(monkeypatch, license_key, status):
    sessions, saved, responsive = [], [], []
    started, release = threading.Event(), threading.Event()
    loop_thread = threading.get_ident()
    monkeypatch.setattr(settings_router.settings, "maxmind_license_key", license_key)
    monkeypatch.setattr(database, "SessionLocal", lambda: OwnedSession(sessions))

    class Client:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def post(self, *args, **kwargs):
            if status is None:
                raise RuntimeError("connection failed")
            return SimpleNamespace(status_code=status)

    def save(db, result):
        started.set()
        responsive.append(release.wait(0.3))
        saved.append((db, result))

    monkeypatch.setattr(settings_router.httpx, "AsyncClient", Client)
    monkeypatch.setattr(settings_router, "save_maxmind_validation_status", save)
    result = asyncio.run(run_with_heartbeat(settings_router.validate_maxmind_license_endpoint(), started, release))

    assert responsive == [True], "license persistence blocked the event loop"
    assert len(sessions) == 1
    assert saved == [(sessions[0], result)]
    assert sessions[0].owner != loop_thread
    assert all(thread == sessions[0].owner for _, thread in sessions[0].operations)
    assert sessions[0].operations[-1][0] == "close"
    assert result["configured"] is bool(license_key)
    assert result["valid"] is bool(license_key and status == 204)


def test_summary_session_lifecycle_stays_in_worker(monkeypatch):
    sessions, used, responsive = [], [], []
    started, release = threading.Event(), threading.Event()
    loop_thread = threading.get_ident()

    def close_delay():
        started.set()
        responsive.append(release.wait(0.3))

    monkeypatch.setattr(database, "SessionLocal", lambda: OwnedSession(sessions, close_delay))
    monkeypatch.setattr(reporting.settings, "admin_email", "")

    def traffic(**kwargs):
        db = kwargs["db"]
        used.append(db)
        db.record("traffic")
        return {"total_sent": 0, "total_received": 0, "sent_failed": 0, "failure_rate": 0}

    def failures(**kwargs):
        db = kwargs["db"]
        used.append(db)
        db.record("failures")
        return {"mailboxes": []}

    async def system():
        return {name: {"active": 0} for name in ("domains", "mailboxes", "aliases")}

    async def storage():
        return {"used_percent": 0}

    async def domains():
        return {"domains": []}

    async def empty():
        return []

    monkeypatch.setattr(reporting, "get_mailbox_stats_summary", traffic)
    monkeypatch.setattr(reporting, "get_all_mailbox_stats", failures)
    monkeypatch.setattr(reporting, "get_mailcow_info", system)
    monkeypatch.setattr(reporting, "get_storage_status", storage)
    monkeypatch.setattr(reporting, "get_all_domains_with_dns", domains)
    monkeypatch.setattr(reporting, "get_monitored_hosts", lambda: {"hosts": []})
    from app.mailcow_api import mailcow_api
    monkeypatch.setattr(mailcow_api, "get_queue", empty)
    monkeypatch.setattr(mailcow_api, "get_quarantine", empty)

    asyncio.run(run_with_heartbeat(reporting.generate_and_send_email(), started, release))

    assert responsive and all(responsive), "summary session cleanup blocked the event loop"
    assert len(sessions) == 1
    assert used == [sessions[0], sessions[0]]
    assert sessions[0].owner != loop_thread
    assert all(thread == sessions[0].owner for _, thread in sessions[0].operations)
    assert sessions[0].operations[-1][0] == "close"


def test_maxmind_persistence_failure_rolls_back_in_worker(monkeypatch):
    sessions = []
    monkeypatch.setattr(settings_router.settings, "maxmind_license_key", "")
    monkeypatch.setattr(database, "SessionLocal", lambda: OwnedSession(sessions))

    def fail(db, result):
        db.record("save")
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(settings_router, "save_maxmind_validation_status", fail)
    with pytest.raises(RuntimeError, match="database unavailable"):
        asyncio.run(settings_router.validate_maxmind_license_endpoint())

    assert len(sessions) == 1
    assert sessions[0].owner != threading.get_ident()
    assert sessions[0].operations == [(operation, sessions[0].owner) for operation in ("save", "rollback", "close")]


@pytest.mark.parametrize("failed_helper", ["get_mailbox_stats_summary", "get_all_mailbox_stats"])
def test_summary_failure_rolls_back_in_worker(monkeypatch, failed_helper):
    sessions = []
    monkeypatch.setattr(database, "SessionLocal", lambda: OwnedSession(sessions))
    monkeypatch.setattr(reporting, "get_mailbox_stats_summary", lambda **kwargs: {})
    monkeypatch.setattr(reporting, "get_all_mailbox_stats", lambda **kwargs: {})

    def fail(**kwargs):
        kwargs["db"].record("query")
        raise RuntimeError("query unavailable")

    monkeypatch.setattr(reporting, failed_helper, fail)
    with pytest.raises(RuntimeError, match="query unavailable"):
        asyncio.run(reporting.get_summary_report())

    assert len(sessions) == 1
    assert sessions[0].owner != threading.get_ident()
    assert sessions[0].operations == [(operation, sessions[0].owner) for operation in ("query", "rollback", "close")]
