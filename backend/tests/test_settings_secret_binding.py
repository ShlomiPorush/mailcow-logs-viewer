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
    # Values go through the same string round trip as the system_settings table
    monkeypatch.setattr(ss, "get_config_overrides_from_db", lambda db, types_: {
        k: ss._deserialize_value(ss._serialize_value(v), k, types_[k]) for k, v in data.items()})
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
    boolean, a number field a number, a select, text or hidden field (the Verify
    SSL buttons) its string value ('' when unset).
    """
    payload = {}
    for key, value in configuration.items():
        if key in rs._SENSITIVE_SETTING_KEYS and value == MASK:
            continue
        if isinstance(value, bool):
            payload[key] = value
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


@pytest.mark.parametrize("verify", ["false", "auto", "true"])
def test_full_form_save_keeps_the_verify_ssl_choice(store, verify):
    store.update({"smtp_verify_ssl": verify, "dmarc_imap_verify_ssl": verify})
    cfg.reload_settings(object())
    payload = _form_payload(rs.get_editable_settings(db=object())["configuration"])
    assert payload["smtp_verify_ssl"] == verify
    _put(payload)
    cfg.reload_settings(object())
    assert cfg.settings.smtp_verify_ssl == verify
    assert cfg.settings.dmarc_imap_verify_ssl == verify


def test_verify_ssl_rejects_an_unknown_value(store):
    with pytest.raises(HTTPException) as exc:
        _put({"smtp_verify_ssl": "maybe"})
    assert exc.value.status_code == 400
    assert "smtp_verify_ssl" in exc.value.detail


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


# On/off settings bound to a secret. A value posted as text is checked, saved
# and loaded as the same True or False: "on" once passed the check as on and
# loaded as off, which turned STARTTLS off with the stored password kept.
BOUND_FLAGS = [
    ("smtp_password", "smtp_use_tls"),
    ("smtp_password", "smtp_use_ssl"),
    ("dmarc_imap_password", "dmarc_imap_use_ssl"),
    ("oauth2_client_secret", "oauth2_use_oidc_discovery"),
]
SPELLINGS = {True: ["on", "ON", " yes ", "1", "true", "t"], False: ["off", "OFF", "no", "0", "false", " n "]}


def _seed_flag(store, flag, value):
    store[flag] = value
    cfg.reload_settings(object())


@pytest.mark.parametrize("secret_value", [MASK, None], ids=["masked", "absent"])
@pytest.mark.parametrize("stored", [True, False])
@pytest.mark.parametrize("secret,flag", BOUND_FLAGS)
def test_a_flag_posted_as_text_takes_effect_as_it_was_checked(store, secret, flag, stored, secret_value):
    _seed_flag(store, flag, stored)
    for spelling in SPELLINGS[stored]:
        body = {flag: spelling}
        if secret_value is not None:
            body[secret] = secret_value
        _put(body)
        assert store[flag] is stored
        cfg.reload_settings(object())
        assert getattr(cfg.settings, flag) is stored, spelling
        assert store[secret] == SEED[secret]


@pytest.mark.parametrize("secret_value", [MASK, None], ids=["masked", "absent"])
@pytest.mark.parametrize("stored", [True, False])
@pytest.mark.parametrize("secret,flag", BOUND_FLAGS)
def test_a_flag_turned_in_text_form_needs_the_secret(store, secret, flag, stored, secret_value):
    _seed_flag(store, flag, stored)
    before = dict(store)
    for spelling in SPELLINGS[not stored]:
        body = {flag: spelling}
        if secret_value is not None:
            body[secret] = secret_value
        with pytest.raises(HTTPException) as exc:
            _put(body)
        assert exc.value.status_code == 400 and "again" in exc.value.detail, spelling
        assert store == before
        assert getattr(cfg.settings, flag) is stored


def test_a_flag_that_is_neither_on_nor_off_is_refused(store):
    before = dict(store)
    for value in ("maybe", "", 2, "enabled"):
        with pytest.raises(HTTPException) as exc:
            _put({"smtp_use_tls": value, "smtp_password": MASK})
        assert exc.value.status_code == 400
        assert exc.value.detail == "Invalid settings for: smtp_use_tls"
    assert store == before


def test_a_flag_stored_as_on_loads_as_on(store):
    # Saved by an earlier version as the text it was posted as
    store.update({"smtp_use_tls": "on", "dmarc_imap_use_ssl": "On", "oauth2_use_oidc_discovery": " yes "})
    cfg.reload_settings(object())
    assert cfg.settings.smtp_use_tls is True
    assert cfg.settings.dmarc_imap_use_ssl is True
    assert cfg.settings.oauth2_use_oidc_discovery is True
