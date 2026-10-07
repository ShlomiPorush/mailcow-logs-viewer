"""A full failed-login table must not refuse the operator's correct password.

The table of clients with failed Basic Auth attempts is bounded. When it was
full, every Basic attempt from an address not already in it got 429 before the
password was checked, and IPv6 addresses were counted one by one, so a single
IPv6 /64 could fill it cheaply and lock the operator out of new logins.
"""
import pytest

from app import auth, session
from app.config import settings
from test_auth_request_limits import client_at, credentials


@pytest.fixture(autouse=True)
def small_table(monkeypatch):
    # Patched on the wrapper, like test_auth_capacity.py, which leaves a value there
    monkeypatch.setattr(settings, "auth_max_failure_clients", 4, raising=False)
    monkeypatch.setattr(settings._inner, "basic_auth_enabled", True)
    monkeypatch.setattr(settings._inner, "auth_enabled", False)
    monkeypatch.setattr(settings._inner, "oauth2_enabled", False)
    monkeypatch.setattr(settings._inner, "auth_username", "admin")
    monkeypatch.setattr(settings._inner, "auth_password", "correct-test-password")
    monkeypatch.setattr(auth, "_next_capacity_cleanup", 0.0)
    auth._auth_failures.clear()
    session._session_store.clear()
    yield
    auth._auth_failures.clear()
    session._session_store.clear()


def test_one_ipv6_network_counts_as_one_client():
    for index in range(1, 9):
        response = client_at(f"2001:db8:1:2::{index:x}").get("/api/auth/verify", headers=credentials("wrong"))
        assert response.status_code == 401
    assert list(auth._auth_failures) == ["2001:db8:1:2::/64"]
    # Its budget is shared: two more wrong guesses from yet another address lock the network
    for _ in range(2):
        client_at("2001:db8:1:2:aaaa::1").get("/api/auth/verify", headers=credentials("wrong"))
    assert client_at("2001:db8:1:2::ffff").get("/api/auth/verify", headers=credentials()).status_code == 429
    # Another network is not affected
    assert client_at("2001:db8:1:3::1").get("/api/auth/verify", headers=credentials()).status_code == 200


def test_ipv4_mapped_addresses_count_as_the_ipv4_address():
    client_at("::ffff:192.0.2.7").get("/api/auth/verify", headers=credentials("wrong"))
    assert list(auth._auth_failures) == ["192.0.2.7"]


def test_full_table_does_not_refuse_a_correct_password_from_a_new_client():
    for network in range(4):
        client_at(f"2001:db8:{network}::1").get("/api/auth/verify", headers=credentials("wrong"))
    assert len(auth._auth_failures) == 4
    operator = client_at("198.51.100.20")
    assert operator.post("/api/auth/session", headers=credentials()).status_code == 200
    assert operator.get("/api/auth/status").json()["authenticated"] is True


def test_full_table_still_counts_wrong_guesses_from_new_clients():
    for network in range(4):
        client_at(f"2001:db8:{network}::1").get("/api/auth/verify", headers=credentials("wrong"))
    newcomer = client_at("198.51.100.21")
    for _ in range(auth._AUTH_MAX_FAILURES):
        assert newcomer.get("/api/auth/verify", headers=credentials("wrong")).status_code == 401
    assert newcomer.get("/api/auth/verify", headers=credentials()).status_code == 429
    assert len(auth._auth_failures) == 4
    # The client whose last failure was oldest made room
    assert "2001:db8::/64" not in auth._auth_failures
