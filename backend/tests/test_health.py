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
