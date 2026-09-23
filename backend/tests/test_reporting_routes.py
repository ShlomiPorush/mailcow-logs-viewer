"""The documented reporting API must be reachable through the real application."""
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from app.routers import reporting


@pytest.fixture
def report_client(monkeypatch):
    for key in ("auth_enabled", "basic_auth_enabled", "oauth2_enabled", "enable_weekly_summary"):
        monkeypatch.setattr(settings._inner, key, False)
    summary = {"timestamp": "2026-01-01T00:00:00Z", "traffic": {"total_sent": 0}}
    data = AsyncMock(return_value=summary)
    send = AsyncMock()
    monkeypatch.setattr(reporting, "get_system_summary_data", data)
    monkeypatch.setattr(reporting, "generate_and_send_email", send)
    return TestClient(app), data, send, summary


def test_summary_get_returns_report_json_from_main_app(report_client):
    client, data, send, summary = report_client
    response = client.get("/api/system/summary")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.json() == summary
    data.assert_awaited_once_with()
    send.assert_not_awaited()


@pytest.mark.parametrize("enabled,force,expected", [(False, False, "skipped"), (True, False, "queued"), (False, True, "queued")])
def test_summary_email_requires_enabled_setting_or_explicit_force(report_client, monkeypatch, enabled, force, expected):
    client, data, send, summary = report_client
    monkeypatch.setattr(settings._inner, "enable_weekly_summary", enabled)
    response = client.post("/api/system/summary/email", params={"force": str(force).lower()})
    assert response.status_code == 200
    assert response.json()["status"] == expected
    assert send.await_count == (1 if expected == "queued" else 0)
    data.assert_not_awaited()


def test_summary_email_validates_force_before_scheduling(report_client):
    client, data, send, summary = report_client
    assert client.post("/api/system/summary/email?force=invalid").status_code == 422
    send.assert_not_awaited()


@pytest.mark.parametrize("method,path", [("GET", "/api/system/summary"), ("POST", "/api/system/summary/email")])
def test_summary_routes_require_authentication(report_client, monkeypatch, method, path):
    client, data, send, summary = report_client
    monkeypatch.setattr(settings._inner, "basic_auth_enabled", True)
    monkeypatch.setattr(settings._inner, "auth_username", "report-test-user")
    monkeypatch.setattr(settings._inner, "auth_password", "report-test-password")
    assert client.request(method, path).status_code == 401
    data.assert_not_awaited()
    send.assert_not_awaited()
    response = client.request(method, path, auth=("report-test-user", "report-test-password"))
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")


def test_summary_routes_are_documented_in_actual_application_schema(report_client):
    schema = report_client[0].get("/openapi.json").json()
    assert "get" in schema["paths"]["/api/system/summary"]
    assert "post" in schema["paths"]["/api/system/summary/email"]
