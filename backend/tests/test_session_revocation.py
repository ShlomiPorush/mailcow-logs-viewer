import base64
import secrets
import threading

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

import app.config as cfg
import app.services.settings_store as ss
from app import auth as auth_module
from app import session
from app.agent_access import store as agent_store
from app.config import settings
from app.database import get_db
from app.main import app
from app.routers import auth as auth_router
from app.routers import settings as settings_router
from sign_in_helpers import revoke_all_sessions


OLD_PASSWORD = secrets.token_hex(16)
NEW_PASSWORD = secrets.token_hex(16)


def basic(password=OLD_PASSWORD):
    return {"Authorization": "Basic " + base64.b64encode(f"admin:{password}".encode()).decode()}


@pytest.fixture(autouse=True)
def store(monkeypatch):
    data = {}
    for key in list(cfg.os.environ):
        if key.startswith(("AUTH_", "BASIC_AUTH", "OAUTH2_", "SESSION_")):
            monkeypatch.delenv(key)
    monkeypatch.setenv("SETTINGS_EDIT_VIA_UI_ENABLED", "true")
    monkeypatch.setattr(ss, "get_config_overrides_from_db", lambda db, types_: {
        k: ss._deserialize_value(ss._serialize_value(v), k, types_[k]) for k, v in data.items()})
    monkeypatch.setattr(settings_router, "save_config_overrides_to_db", lambda db, values: data.update(values))
    monkeypatch.setattr(settings_router.users_store, "check_sign_in_settings", lambda db, before, allowed: None)
    monkeypatch.setattr(settings_router, "has_config_overrides_in_db", lambda db: bool(data))
    monkeypatch.setattr(settings_router, "cleanup_disabled_feature_data", lambda db: None)
    monkeypatch.setattr(settings_router, "reschedule_interval_jobs", lambda: None)
    monkeypatch.setattr(settings_router.mailcow_api, "reload_config", lambda: None)
    monkeypatch.setattr(settings_router.oauth2_client, "reload_config", lambda: None)
    data.update({"basic_auth_enabled": True, "oauth2_enabled": False,
                 "auth_username": "admin", "auth_password": OLD_PASSWORD})
    cfg.reload_settings(object())
    app.dependency_overrides[get_db] = lambda: object()
    session._session_store.clear()
    yield data
    app.dependency_overrides.pop(get_db, None)
    session._session_store.clear()
    monkeypatch.undo()
    cfg.reload_settings()


def signed_in():
    client = TestClient(app)
    assert client.post("/api/auth/session", headers=basic()).status_code == 200
    return client


@pytest.mark.parametrize("change", [
    {"auth_password": NEW_PASSWORD},
    {"auth_username": "operator"},
    {"oauth2_client_secret": secrets.token_hex(16)},
    {"oauth2_issuer_url": "https://id.example.com"},
])
def test_auth_change_revokes_other_sessions_and_keeps_the_operator_signed_in(change):
    stolen, operator = signed_in(), signed_in()
    response = operator.put("/api/settings", json=change)
    assert response.status_code == 200
    assert stolen.get("/api/auth/verify").status_code == 401
    assert stolen.put("/api/settings", json={"auth_password": secrets.token_hex(16)}).status_code == 401
    assert "session_id=" in response.headers.get("set-cookie", "")
    assert operator.get("/api/auth/verify").status_code == 200
    assert len(session._session_store) == 1


def test_disabling_authentication_clears_sessions():
    operator = signed_in()
    assert operator.put("/api/settings", json={"basic_auth_enabled": False}).status_code == 200
    assert not session._session_store


def test_unrelated_change_keeps_sessions():
    other, operator = signed_in(), signed_in()
    response = operator.put("/api/settings", json={"app_title": "Test viewer"})
    assert response.status_code == 200
    assert "set-cookie" not in response.headers
    assert other.get("/api/auth/verify").status_code == 200
    assert len(session._session_store) == 2


def test_resaving_the_same_credentials_keeps_sessions():
    other, operator = signed_in(), signed_in()
    assert operator.put("/api/settings", json={"auth_username": "admin"}).status_code == 200
    assert other.get("/api/auth/verify").status_code == 200


def test_revocation_is_decided_from_the_saved_settings(monkeypatch):
    stolen, operator = signed_in(), signed_in()
    old = cfg.build_settings(object())
    real = settings_router._record_list_transition

    def put_old_settings_back(*args, **kwargs):
        cfg._settings_wrapper._inner = old
        return real(*args, **kwargs)

    monkeypatch.setattr(settings_router, "_record_list_transition", put_old_settings_back)
    assert operator.put("/api/settings", json={"auth_password": NEW_PASSWORD}).status_code == 200
    assert stolen.get("/api/auth/verify").status_code == 401


def test_a_reload_elsewhere_cannot_bring_the_old_password_back(store, monkeypatch):
    stolen, operator = signed_in(), signed_in()
    get_arrived, get_read, put_reloaded = threading.Event(), threading.Event(), threading.Event()
    get_thread, errors = {}, []
    read = ss.get_config_overrides_from_db

    def is_get():
        return threading.current_thread() is get_thread.get("thread")

    def read_stored(db, types_):
        values = read(db, types_)
        if is_get():
            get_read.set()
            get_arrived.set()
            put_reloaded.wait(timeout=5)
        return values

    class WatchedLock:
        def __init__(self, lock):
            self.lock = lock

        def __enter__(self):
            if is_get():
                get_arrived.set()
            return self.lock.__enter__()

        def __exit__(self, *exc):
            return self.lock.__exit__(*exc)

    def get_settings():
        try:
            settings_router.get_editable_settings(db=object())
        except Exception as e:
            errors.append(e)

    def save(db, values):
        thread = get_thread["thread"] = threading.Thread(target=get_settings, daemon=True)
        thread.start()
        assert get_arrived.wait(timeout=5)
        store.update(values)

    real_transition = settings_router._record_list_transition

    def after_reload(*args, **kwargs):
        put_reloaded.set()
        if get_read.is_set():
            get_thread["thread"].join(timeout=5)
        return real_transition(*args, **kwargs)

    monkeypatch.setattr(cfg, "settings_reload_lock", WatchedLock(getattr(cfg, "settings_reload_lock", None)),
                        raising=False)
    monkeypatch.setattr(ss, "get_config_overrides_from_db", read_stored)
    monkeypatch.setattr(settings_router, "save_config_overrides_to_db", save)
    monkeypatch.setattr(settings_router, "_record_list_transition", after_reload)
    try:
        assert operator.put("/api/settings", json={"auth_password": NEW_PASSWORD}).status_code == 200
    finally:
        put_reloaded.set()
        get_thread["thread"].join(timeout=5)
    assert not get_thread["thread"].is_alive() and not errors
    assert settings.auth_password == NEW_PASSWORD
    assert stolen.get("/api/auth/verify").status_code == 401
    assert TestClient(app).post("/api/auth/session", headers=basic()).status_code == 401
    assert TestClient(app).post("/api/auth/session", headers=basic(NEW_PASSWORD)).status_code == 200


def test_a_login_let_in_before_a_password_change_gets_no_session(monkeypatch):
    check = auth_module.verify_credentials

    def accept_then_change(username, password):
        accepted = check(username, password)
        revoke_all_sessions()
        return accepted

    monkeypatch.setattr(auth_module, "verify_credentials", accept_then_change)
    client = TestClient(app)
    response = client.post("/api/auth/session", headers=basic())
    assert response.status_code == 409
    assert "session_id" not in client.cookies
    assert not session._session_store


def test_a_session_cannot_be_exchanged_for_a_new_one(monkeypatch):
    stolen = signed_in()
    assert stolen.post("/api/auth/session").status_code == 401
    revoke_all_sessions()
    assert stolen.post("/api/auth/session").status_code == 401
    assert not session._session_store


def _admitted_request(generation=None):
    request = Request({"type": "http", "method": "POST", "path": "/api/auth/session",
                       "headers": [(b"authorization", basic()["Authorization"].encode())], "query_string": b""})
    if generation is not None:
        request.state.auth_generation = generation
    return request


def test_a_login_let_in_while_sign_in_was_off_gets_no_session_once_it_is_on():
    request = _admitted_request(session.auth_generation())
    revoke_all_sessions()
    with pytest.raises(HTTPException) as refused:
        auth_router.create_basic_auth_session(request)
    assert refused.value.status_code == 409
    assert not session._session_store


def test_a_login_the_middleware_did_not_see_gets_no_session():
    with pytest.raises(HTTPException) as refused:
        auth_router.create_basic_auth_session(_admitted_request())
    assert refused.value.status_code == 409
    assert not session._session_store


def test_the_saver_is_not_signed_in_again_after_a_later_change(monkeypatch):
    stolen, operator = signed_in(), signed_in()

    def another_change_meanwhile(db):
        revoke_all_sessions()

    monkeypatch.setattr(agent_store, "check_sign_in_unchanged", another_change_meanwhile)
    response = operator.put("/api/settings", json={"auth_password": NEW_PASSWORD})
    assert response.status_code == 200
    assert "session_id=" not in response.headers.get("set-cookie", "")
    assert operator.get("/api/auth/verify").status_code == 401
    assert stolen.get("/api/auth/verify").status_code == 401
    assert not session._session_store


def test_the_oauth2_client_takes_the_new_provider_before_new_sessions_begin(monkeypatch):
    client = settings_router.oauth2_client
    for name in ("issuer_url", "client_id", "client_secret", "redirect_uri", "scopes",
                 "authorization_url", "token_url", "userinfo_url", "_discovery_cache"):
        monkeypatch.setattr(client, name, getattr(client, name, None), raising=False)
    monkeypatch.setattr(client, "reload_config", type(client).reload_config.__get__(client))
    token_url_at_revocation = []
    revoke = settings_router.revoke_all_sessions_keeping

    def note_then_revoke(*args):
        token_url_at_revocation.append(client.token_url)
        return revoke(*args)

    monkeypatch.setattr(settings_router, "revoke_all_sessions_keeping", note_then_revoke)
    operator = signed_in()
    response = operator.put("/api/settings", json={"oauth2_token_url": "https://id.example.test/new-token"})
    assert response.status_code == 200
    assert token_url_at_revocation == ["https://id.example.test/new-token"]
