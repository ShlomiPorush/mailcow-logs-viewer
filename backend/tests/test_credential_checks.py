"""
Credential checks: one harmless request tells whether mailcow accepts the
Read-Write API key and whether Rspamd accepts its password, and the last
result is kept only for the address and secret it ran against.
"""
import asyncio
import uuid
from contextlib import contextmanager

import httpx
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from app.database import engine
from app.mailcow_api import MailcowAPI
from app.models import Base, SystemSetting
from app.routers import settings as settings_router
from app.services import settings_store


def _client(handler):
    api = MailcowAPI()
    api.base_url = "https://mail.example.com"
    api.headers_rw = {"X-API-Key": "rw-key", "Content-Type": "application/json"}
    requests = []

    def record(request):
        requests.append(request)
        return handler(request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(record))
    api._get_client = lambda: client
    return api, requests


# ── mailcow Read-Write API key ────────────────────────────────────────────

@pytest.mark.parametrize("status, valid, error", [
    (404, True, None),
    (403, False, "read_only"),
    (401, False, "rejected"),
    (500, False, "unexpected"),
])
def test_rw_key_check_reads_the_mailcow_answer(status, valid, error):
    api, requests = _client(lambda r: httpx.Response(status, json={"type": "error", "msg": "x"}))
    result = asyncio.run(api.check_rw_key())
    assert result["configured"] is True
    assert result["valid"] is valid
    assert result["error"] == error
    # One request, no retry: every rejection counts as a failed login for Fail2ban
    assert len(requests) == 1
    request = requests[0]
    assert request.method == "POST"
    assert request.url.path == "/api/v1/edit/mlv-key-check"
    assert request.headers["X-API-Key"] == "rw-key"


def test_rw_key_check_reports_an_unreachable_mailcow():
    def fail(request):
        raise httpx.ConnectError("refused", request=request)
    api, requests = _client(fail)
    result = asyncio.run(api.check_rw_key())
    assert result == {"configured": True, "valid": False, "error": "connection"}
    assert len(requests) == 1


def test_rw_key_check_without_a_key_sends_nothing():
    api, requests = _client(lambda r: httpx.Response(404))
    api.headers_rw = None
    assert asyncio.run(api.check_rw_key()) == {"configured": False, "valid": False, "error": None}
    assert requests == []


# ── Rspamd password ───────────────────────────────────────────────────────

@pytest.fixture
def rspamd(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings._inner, "rspamd_password", "rspamd-pw")
    monkeypatch.setattr(settings._inner, "rspamd_url", "")
    return settings


@pytest.mark.parametrize("status, body, valid, error", [
    (200, {"auth": "ok", "read_only": False}, True, None),
    (200, {"error": "something else"}, False, "unexpected"),
    (401, {"error": "Unauthorized"}, False, "rejected"),
    (403, {"error": "Unauthorized"}, False, "rejected"),
    (302, {}, False, "redirected"),
    (500, {}, False, "unexpected"),
])
def test_rspamd_check_reads_the_rspamd_answer(rspamd, status, body, valid, error):
    api, requests = _client(lambda r: httpx.Response(status, json=body))
    result = asyncio.run(api.check_rspamd_password())
    assert (result["configured"], result["valid"], result["error"]) == (True, valid, error)
    assert len(requests) == 1
    request = requests[0]
    assert request.method == "GET"
    assert str(request.url) == "https://mail.example.com/rspamd/auth"
    assert request.headers["Password"] == "rspamd-pw"


def test_rspamd_check_uses_the_direct_rspamd_url(rspamd, monkeypatch):
    monkeypatch.setattr(rspamd._inner, "rspamd_url", "http://rspamd-mailcow:11334/")
    api, requests = _client(lambda r: httpx.Response(200, json={"auth": "ok"}))
    assert asyncio.run(api.check_rspamd_password())["valid"] is True
    assert str(requests[0].url) == "http://rspamd-mailcow:11334/auth"


def test_rspamd_check_reports_an_unreachable_rspamd(rspamd):
    def fail(request):
        raise httpx.ConnectError("refused", request=request)
    api, _ = _client(fail)
    assert asyncio.run(api.check_rspamd_password()) == {"configured": True, "valid": False, "error": "connection"}


def test_rspamd_check_without_a_password_sends_nothing(rspamd, monkeypatch):
    monkeypatch.setattr(rspamd._inner, "rspamd_password", None)
    api, requests = _client(lambda r: httpx.Response(200))
    assert asyncio.run(api.check_rspamd_password()) == {"configured": False, "valid": False, "error": None}
    assert requests == []


# ── Endpoints and stored status ───────────────────────────────────────────

@pytest.mark.parametrize("name, method, endpoint", [
    ("mailcow_rw_key", "check_rw_key", "validate_mailcow_rw_key_endpoint"),
    ("rspamd_password", "check_rspamd_password", "validate_rspamd_password_endpoint"),
])
def test_endpoints_keep_only_checks_of_a_configured_credential(monkeypatch, name, method, endpoint):
    saved = []
    monkeypatch.setattr(settings_router, "_persist_credential_status_worker",
                        lambda n, result, fingerprint: saved.append((n, result)))

    async def accepted():
        return {"configured": True, "valid": True, "error": None}

    async def missing():
        return {"configured": False, "valid": False, "error": None}

    monkeypatch.setattr(settings_router.mailcow_api, method, accepted)
    assert asyncio.run(getattr(settings_router, endpoint)())["valid"] is True
    monkeypatch.setattr(settings_router.mailcow_api, method, missing)
    asyncio.run(getattr(settings_router, endpoint)())
    assert saved == [(name, {"configured": True, "valid": True, "error": None})]


def test_status_is_forgotten_when_the_address_or_secret_changes():
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        pytest.skip("PostgreSQL not available")
    schema = "credential_check_test_" + uuid.uuid4().hex
    with engine.begin() as conn:
        conn.execute(text(f"CREATE SCHEMA {schema}"))
    isolated = create_engine(engine.url, connect_args={"options": f"-csearch_path={schema}"})

    @contextmanager
    def session():
        with Session(isolated) as db:
            yield db
    try:
        Base.metadata.create_all(isolated, tables=[SystemSetting.__table__])
        current = settings_store.credential_fingerprint("https://mail.example.com", "rw-key")
        with session() as db:
            assert settings_store.get_credential_check_status(db, "mailcow_rw_key", current) is None
            settings_store.save_credential_check_status(
                db, "mailcow_rw_key", {"configured": True, "valid": False, "error": "rejected", "http_status": 401}, current)
        with session() as db:
            status = settings_store.get_credential_check_status(db, "mailcow_rw_key", current)
            assert status["error"] == "rejected" and status["checked_at"]
            assert "fingerprint" not in status
            # The secret itself is never stored with the status
            assert "rw-key" not in db.query(SystemSetting).one().value
            # Each credential keeps its own result
            assert settings_store.get_credential_check_status(db, "rspamd_password", current) is None
            for url, key in [("https://mail.example.com", "new-key"), ("https://other.example.com", "rw-key")]:
                changed = settings_store.credential_fingerprint(url, key)
                assert settings_store.get_credential_check_status(db, "mailcow_rw_key", changed) is None
    finally:
        isolated.dispose()
        with engine.begin() as conn:
            conn.execute(text(f"DROP SCHEMA {schema} CASCADE"))
