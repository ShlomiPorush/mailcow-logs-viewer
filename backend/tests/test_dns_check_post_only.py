"""A domain's DNS check runs only from a POST sent by the app's own pages.

GET /api/domains/{domain}/dns-check ran the DNS, MTA-STS and DANE probes for
any valid domain. The origin guard only inspects POST, PUT, PATCH and DELETE,
authentication is off by default and the session cookie is SameSite Lax, so a
link on another site could make the app probe any domain. The GET is gone; the
SPA and agents use POST /api/domains/{domain}/check-dns.
"""
import pytest
from fastapi.testclient import TestClient

from app import auth, session
from app.agent_access import scopes
from app.config import settings
from app.main import app
from app.routers import domains

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
def checks(monkeypatch):
    checked, stored = [], []

    async def fake_check(domain):
        checked.append(domain)
        return {"domain": domain}

    monkeypatch.setattr(domains, "check_domain_dns", fake_check)
    monkeypatch.setattr(domains, "store_dns_check_worker", lambda domain, *a, **k: stored.append(domain))
    return checked, stored


def client():
    return TestClient(app, base_url=APP)


def test_get_does_not_start_a_check(checks):
    response = client().get("/api/domains/example.com/dns-check")
    assert response.status_code == 404
    assert response.json() == {"detail": "Not Found"}
    assert checks == ([], [])


def test_agents_are_not_offered_the_get():
    assert ("GET", "/api/domains/{domain}/dns-check") not in scopes.POLICY
    assert scopes.POLICY[("POST", "/api/domains/{domain}/check-dns")].kind == scopes.WRITE


def test_cross_site_post_does_not_start_a_check(checks):
    response = client().post("/api/domains/example.com/check-dns", headers={"Origin": "https://evil.invalid"})
    assert response.status_code == 403
    assert checks == ([], [])


def test_same_origin_post_checks_and_stores(checks):
    response = client().post("/api/domains/example.com/check-dns", headers={"Origin": APP})
    assert response.status_code == 200
    assert response.json()["data"] == {"domain": "example.com"}
    assert checks == (["example.com"], ["example.com"])
