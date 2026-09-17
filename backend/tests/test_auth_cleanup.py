"""Expired authentication records are reclaimed without touching live records."""
import asyncio
from collections import deque
from datetime import datetime, timedelta
from app import auth, session


def test_cleanup_removes_idle_clients_and_keeps_recent_failures(monkeypatch):
    monkeypatch.setattr(auth, "_auth_failures", {
        "192.0.2.1": deque([1.0]),
        "192.0.2.2": deque([1.0, 999.0]),
        "192.0.2.3": deque([999.0] * auth._AUTH_MAX_FAILURES),
    })
    monkeypatch.setattr(auth.time, "time", lambda: 1000.0)
    auth.cleanup_expired_auth_failures()
    assert "192.0.2.1" not in auth._auth_failures
    assert list(auth._auth_failures["192.0.2.2"]) == [999.0]
    assert auth._is_rate_limited("192.0.2.3")


def test_cleanup_removes_expired_sessions_without_a_cookie_lookup(monkeypatch):
    now = datetime.utcnow()
    active = {"expires_at": (now + timedelta(hours=1)).isoformat()}
    monkeypatch.setattr(session, "_session_store", {
        "expired": {"expires_at": (now - timedelta(hours=1)).isoformat()},
        "active": active,
    })
    assert session.cleanup_expired_sessions() == 1
    assert session._session_store == {"active": active}


def test_maintenance_runs_repeatedly_and_stops_on_context_exit(monkeypatch):
    from app.services import auth_cleanup
    calls = []
    monkeypatch.setattr(auth_cleanup, "CLEANUP_INTERVAL_SECONDS", 0.001)
    monkeypatch.setattr(auth_cleanup, "cleanup_expired_sessions", lambda: calls.append("sessions"))
    monkeypatch.setattr(auth_cleanup, "cleanup_expired_auth_failures", lambda: calls.append("failures"))
    monkeypatch.setattr(auth_cleanup, "_cleanup_oauth_states", lambda: calls.append("states"))

    async def run():
        async with auth_cleanup.auth_store_maintenance():
            for _ in range(100):
                if len(calls) >= 6:
                    break
                await asyncio.sleep(0.002)
            assert calls[:6] == ["sessions", "failures", "states"] * 2
        count = len(calls)
        await asyncio.sleep(0.01)
        assert len(calls) == count
    asyncio.run(run())


def test_cleanup_failure_does_not_stop_other_stores_or_future_sweeps(monkeypatch):
    from app.services import auth_cleanup
    calls = []
    def broken():
        calls.append("broken")
        raise ValueError("fixture failure")
    monkeypatch.setattr(auth_cleanup, "CLEANUP_INTERVAL_SECONDS", 0.001)
    monkeypatch.setattr(auth_cleanup, "cleanup_expired_sessions", broken)
    monkeypatch.setattr(auth_cleanup, "cleanup_expired_auth_failures", lambda: calls.append("failures"))
    monkeypatch.setattr(auth_cleanup, "_cleanup_oauth_states", lambda: calls.append("states"))
    async def run():
        async with auth_cleanup.auth_store_maintenance():
            for _ in range(100):
                if len(calls) >= 6:
                    break
                await asyncio.sleep(0.002)
            assert calls[:6] == ["broken", "failures", "states"] * 2
    asyncio.run(run())
