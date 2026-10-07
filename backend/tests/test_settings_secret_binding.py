"""A masked secret stays bound to the server it was entered for.

GET /api/settings never returns stored secrets; it returns the mask instead,
and PUT treats the mask (or an absent key) as "keep the stored value". Without
a binding, a session that never saw the SMTP password could change only the
SMTP host and receive the stored password at a server of its choice. Changing
a server a stored secret is sent to must therefore come with the secret.

The Settings page posts every editable key on each save, with '' for unset
text fields, so an unchanged save must keep working.
"""
import types

import pytest
from fastapi import HTTPException

import app.config as cfg
import app.routers.settings as rs
import app.services.settings_store as ss
from app.config import EDITABLE_SETTING_KEYS

MASK = rs.MASK_PLACEHOLDER

SEED = {
    "smtp_enabled": True, "smtp_host": "smtp.example.com", "smtp_port": 587, "smtp_use_tls": True,
    "smtp_use_ssl": False, "smtp_user": "notify@example.com", "smtp_password": "Dummy-Smtp-Secret-1",
    "rspamd_url": "http://rspamd.example.com:11334", "rspamd_password": "Dummy-Rspamd-Secret-2",
    "dmarc_imap_enabled": True, "dmarc_imap_host": "imap.example.com", "dmarc_imap_port": 993,
    "dmarc_imap_use_ssl": True, "dmarc_imap_user": "dmarc@example.com", "dmarc_imap_password": "Dummy-Imap-Secret-3",
    "oauth2_client_id": "dash", "oauth2_client_secret": "Dummy-OAuth-Secret-4",
    "oauth2_issuer_url": "https://idp.example.com", "oauth2_use_oidc_discovery": True,
}


@pytest.fixture
def store(monkeypatch):
    """Real update_settings and build_settings; only the system_settings table is a dict."""
    data = {}
    for key in list(cfg.os.environ):
        if key.startswith(("SMTP_", "RSPAMD_", "DMARC_IMAP_", "OAUTH2_")):
            monkeypatch.delenv(key)
    monkeypatch.setenv("SETTINGS_EDIT_VIA_UI_ENABLED", "true")
    monkeypatch.setattr(ss, "get_config_overrides_from_db", lambda db, types_: dict(data))
    monkeypatch.setattr(rs, "save_config_overrides_to_db", lambda db, ov: data.update(ov))
    monkeypatch.setattr(rs, "has_config_overrides_in_db", lambda db: bool(data))
    monkeypatch.setattr(rs, "cleanup_disabled_feature_data", lambda db: None)
    monkeypatch.setattr(rs, "reschedule_interval_jobs", lambda: None)
    monkeypatch.setattr(rs, "clear_maxmind_validation_status", lambda db: None)
    monkeypatch.setattr(rs, "mailcow_api", types.SimpleNamespace(
        reload_config=lambda: None, has_rw_key=False))
    monkeypatch.setattr(rs, "oauth2_client", types.SimpleNamespace(reload_config=lambda: None))
    data.update(SEED)
    cfg.reload_settings(object())
    yield data
    monkeypatch.undo()
    cfg.reload_settings()


def _put(body):
    return rs.update_settings(dict(body), db=object())


def _form_payload(configuration):
    """What the Settings page sends on Save (frontend/settings.js, form.onsubmit).

    Every editable key is posted. A masked secret is left out, a checkbox is a
    boolean, a number field a number, a select or text field its string value
    ('' when unset). Settings that are null render as a text field or select.
    """
    payload = {}
    for key, value in configuration.items():
        if key in rs._SENSITIVE_SETTING_KEYS and value == MASK:
            continue
        if isinstance(value, bool) and key not in getattr(rs, "_TRI_STATE_KEYS", ()):
            payload[key] = value
        elif isinstance(value, bool):
            payload[key] = "true" if value else "false"
        elif isinstance(value, (int, float)):
            payload[key] = value
        else:
            payload[key] = "" if value is None else str(value)
    return payload


MOVES = [
    ("smtp_password", {"smtp_host": "collector.example.net"}),
    ("smtp_password", {"smtp_port": 25}),
    ("smtp_password", {"smtp_use_tls": False}),
    ("smtp_password", {"smtp_use_ssl": True}),
    ("smtp_password", {"smtp_user": "other@example.net"}),
    ("rspamd_password", {"rspamd_url": "http://collector.example.net:11334"}),
    ("dmarc_imap_password", {"dmarc_imap_host": "collector.example.net"}),
    ("dmarc_imap_password", {"dmarc_imap_port": 143}),
    ("dmarc_imap_password", {"dmarc_imap_use_ssl": False}),
    ("dmarc_imap_password", {"dmarc_imap_user": "other@example.net"}),
    ("oauth2_client_secret", {"oauth2_issuer_url": "https://collector.example.net"}),
    ("oauth2_client_secret", {"oauth2_token_url": "https://collector.example.net/token"}),
    ("oauth2_client_secret", {"oauth2_authorization_url": "https://collector.example.net/auth"}),
    ("oauth2_client_secret", {"oauth2_userinfo_url": "https://collector.example.net/me"}),
    ("oauth2_client_secret", {"oauth2_use_oidc_discovery": False}),
]


@pytest.mark.parametrize("secret_value", [MASK, None], ids=["masked", "absent"])
@pytest.mark.parametrize("secret,change", MOVES)
def test_moving_a_stored_secret_to_another_server_needs_the_secret(store, secret, change, secret_value):
    before = dict(store)
    body = dict(change)
    if secret_value is not None:
        body[secret] = secret_value
    with pytest.raises(HTTPException) as exc:
        _put(body)
    assert exc.value.status_code == 400
    assert "again" in exc.value.detail
    assert store == before
    for key in change:
        assert getattr(cfg.settings, key) == SEED.get(key, getattr(cfg.settings, key))


@pytest.mark.parametrize("secret,change", MOVES)
def test_a_new_secret_may_come_with_a_new_server(store, secret, change):
    _put({**change, secret: "Dummy-New-Secret"})
    assert store[secret] == "Dummy-New-Secret"
    for key, value in change.items():
        assert store[key] == value


def test_clearing_the_secret_with_the_server_change_is_allowed(store):
    _put({"smtp_host": "collector.example.net", "smtp_password": ""})
    assert store["smtp_host"] == "collector.example.net"
    assert store["smtp_password"] == ""


def test_unchanged_full_form_save_succeeds(store):
    configuration = rs.get_editable_settings(db=object())["configuration"]
    payload = _form_payload(configuration)
    # The page posts '' for every unset text field, e.g. the manual OAuth URLs
    assert payload["oauth2_token_url"] == ""
    assert payload["oauth2_authorization_url"] == ""
    assert "smtp_password" not in payload
    assert set(payload) >= {"smtp_host", "smtp_port", "rspamd_url", "dmarc_imap_host", "oauth2_issuer_url"}
    result = _put(payload)
    assert result["configuration"]["smtp_password"] == MASK
    assert store["smtp_password"] == SEED["smtp_password"]


def test_form_save_changing_only_unrelated_fields_succeeds(store):
    payload = _form_payload(rs.get_editable_settings(db=object())["configuration"])
    payload["smtp_from"] = "alerts@example.com"
    payload["dmarc_imap_folder"] = "Reports"
    _put(payload)
    assert store["smtp_from"] == "alerts@example.com"


@pytest.mark.parametrize("change", [
    {"rspamd_url": "http://rspamd.example.com:11334/"},
    {"rspamd_url": " http://rspamd.example.com:11334 "},
    {"smtp_port": "587"},
    {"oauth2_token_url": ""},
    {"oauth2_token_url": None},
])
def test_equivalent_values_are_not_a_server_change(store, change):
    _put({**change, "rspamd_password": MASK, "smtp_password": MASK, "oauth2_client_secret": MASK})


def test_server_change_without_a_stored_secret_is_allowed(store):
    store["rspamd_password"] = ""
    cfg.reload_settings(object())
    _put({"rspamd_url": "http://other.example.net:11334"})
    assert store["rspamd_url"] == "http://other.example.net:11334"


def test_env_locked_server_is_ignored(store, monkeypatch):
    # ENV wins over the database, so a posted value for an ENV-set key changes nothing
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    cfg.reload_settings(object())
    _put({"smtp_host": "collector.example.net", "smtp_password": MASK})


def test_secret_from_env_cannot_follow_a_server_change(store, monkeypatch):
    # The page cannot re-enter a secret that ENV sets, so the server must be changed there too
    monkeypatch.setenv("SMTP_PASSWORD", "Dummy-Env-Secret")
    cfg.reload_settings(object())
    with pytest.raises(HTTPException) as exc:
        _put({"smtp_host": "collector.example.net"})
    assert exc.value.status_code == 400
    assert "SMTP_PASSWORD" in exc.value.detail


def test_every_bound_key_is_editable():
    bindings = getattr(rs, "_SECRET_BINDINGS")
    for secret, endpoints in bindings.items():
        assert secret in rs._SENSITIVE_SETTING_KEYS
        assert secret in EDITABLE_SETTING_KEYS
        assert set(endpoints) <= EDITABLE_SETTING_KEYS
