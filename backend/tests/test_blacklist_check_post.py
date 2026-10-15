"""A blacklist check runs only from a POST sent by the app's own pages.

The check was a GET, and the origin guard only inspects POST, PUT, PATCH and
DELETE. Authentication is off by default and the session cookie is SameSite
Lax, so a link or image on another site could start the all-hosts check, and
with it the blacklist alert to every configured recipient.
"""
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from app import auth, scheduler, session
from app.config import settings
from app.main import app

APP = "http://logs.example.test"


@pytest.fixture(autouse=True)
def no_auth(monkeypatch):
    monkeypatch.setattr(settings._inner, "auth_enabled", False)
    monkeypatch.setattr(settings._inner, "basic_auth_enabled", False)
    monkeypatch.setattr(settings._inner, "oauth2_enabled", False)
    yield
    session._session_store.clear()
    auth._auth_failures.clear()


@pytest.fixture
def job(monkeypatch):
    mock = AsyncMock()
    monkeypatch.setattr(scheduler, "check_monitored_hosts_job", mock)
    return mock


def client():
    return TestClient(app, base_url=APP)


def test_get_does_not_start_a_check(job):
    response = client().get("/api/blacklist/check")
    assert response.status_code == 405
    job.assert_not_called()


def test_cross_site_post_does_not_start_a_check(job):
    response = client().post("/api/blacklist/check", headers={"Origin": "https://evil.invalid"})
    assert response.status_code == 403
    job.assert_not_called()


def test_same_origin_post_starts_the_check(job):
    response = client().post("/api/blacklist/check?force=true", headers={"Origin": APP})
    assert response.status_code == 200
    assert response.json()["status"] == "started"
    job.assert_called_once_with(force=True)
