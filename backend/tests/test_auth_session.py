"""Tests for auth rate limiting and session signing (no DB required)."""
from app.auth import (
    _AUTH_MAX_FAILURES,
    _clear_auth_failures,
    _is_rate_limited,
    _record_auth_failure,
)
from app import session


def test_rate_limiter_blocks_after_max_failures():
    ip = "198.51.100.7"
    _clear_auth_failures(ip)
    for _ in range(_AUTH_MAX_FAILURES - 1):
        _record_auth_failure(ip)
    assert not _is_rate_limited(ip)
    _record_auth_failure(ip)
    assert _is_rate_limited(ip)
    _clear_auth_failures(ip)
    assert not _is_rate_limited(ip)


def test_rate_limiter_isolated_per_ip():
    _clear_auth_failures("198.51.100.8")
    _clear_auth_failures("198.51.100.9")
    for _ in range(_AUTH_MAX_FAILURES):
        _record_auth_failure("198.51.100.8")
    assert _is_rate_limited("198.51.100.8")
    assert not _is_rate_limited("198.51.100.9")
    _clear_auth_failures("198.51.100.8")


def test_session_fallback_key_is_stable():
    # Without SESSION_SECRET_KEY configured the fallback key must be generated
    # once per process — a per-call key would silently break all OAuth2 logins.
    assert session.get_session_secret_key() == session.get_session_secret_key()


def test_session_sign_verify_roundtrip():
    signed = session.create_session({"email": "user@example.com"})
    data = session.get_session(signed)
    assert data is not None
    assert data["user_info"]["email"] == "user@example.com"
    assert session.delete_session(signed) is True
    assert session.get_session(signed) is None


def test_session_rejects_tampered_id():
    signed = session.create_session({"email": "user@example.com"})
    assert session.get_session(signed + "x") is None
    session.delete_session(signed)
