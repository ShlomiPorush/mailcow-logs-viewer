import pytest

from app.auth import (
    _AUTH_MAX_FAILURES,
    _clear_auth_failures,
    _is_rate_limited,
    _record_auth_failure,
)
from app import session, user_access


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
    assert session.get_session_secret_key() == session.get_session_secret_key()


USER_INFO = {"email": "user@example.com"}


def _create():
    return session.create_session(USER_INFO, generation=session.auth_generation(),
                                  principal=user_access.oauth2_ref(USER_INFO))


def test_session_sign_verify_roundtrip():
    signed = _create()
    data = session.get_session(signed)
    assert data is not None
    assert data["user_info"]["email"] == "user@example.com"
    assert session.delete_session(signed) is True
    assert session.get_session(signed) is None


def test_session_rejects_tampered_id():
    signed = _create()
    assert session.get_session(signed + "x") is None
    session.delete_session(signed)


def test_a_session_cannot_be_created_without_its_principal():
    with pytest.raises(TypeError):
        session.create_session(USER_INFO, generation=session.auth_generation())
