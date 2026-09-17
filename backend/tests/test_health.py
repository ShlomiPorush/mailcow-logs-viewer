"""Verify the public health status consumed by container monitoring."""
import pytest
from fastapi.testclient import TestClient
from app import main
from app.config import settings


@pytest.mark.parametrize("connected,code", [(True, 200), (False, 503)])
def test_health_http_status_matches_database_state(monkeypatch, connected, code):
    monkeypatch.setattr(main, "check_db_connection", lambda: connected)
    monkeypatch.setattr(settings._inner, "basic_auth_enabled", True)
    monkeypatch.setattr(settings._inner, "auth_enabled", True)
    response = TestClient(main.app).get("/api/health")
    assert response.status_code == code
    assert response.json() == {
        "status": "healthy" if connected else "unhealthy",
        "database": "connected" if connected else "disconnected",
    }


def test_slow_health_probe_does_not_block_other_requests(monkeypatch):
    import asyncio
    import threading
    import httpx

    started = threading.Event()
    release = threading.Event()
    finished = threading.Event()

    def slow_probe():
        started.set()
        try:
            release.wait(timeout=2)
            return True
        finally:
            finished.set()

    monkeypatch.setattr(main, "check_db_connection", slow_probe)

    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app),
                                     base_url="http://testserver") as client:
            health = asyncio.create_task(client.get("/api/health"))
            try:
                assert await asyncio.to_thread(started.wait, 3)
                info = await asyncio.wait_for(client.get("/api/info"), 1)
                assert info.status_code == 200
                assert not finished.is_set(), "health probe blocked unrelated requests"
            finally:
                release.set()
                result = await health
            assert result.status_code == 200
    asyncio.run(run())
