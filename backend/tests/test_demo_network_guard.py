"""
The demo image's network guard: every outbound path a service could take
fails like an unreachable network, while loopback and the database host stay
reachable. Addresses are RFC 5737 documentation ranges and example.com names,
so a guard that fails open still cannot reach a real server.
"""
import asyncio
import errno
import smtplib
import socket
import threading

import httpx
import pytest

from demo import network_guard


@pytest.fixture
def guard():
    network_guard.install(allowed_hosts=["db.demo.test"])
    try:
        yield
    finally:
        network_guard.uninstall()


@pytest.fixture
def loopback_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    accepted = []

    def accept():
        conn, _ = server.accept()
        accepted.append(conn)

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    try:
        yield server.getsockname()
    finally:
        thread.join(timeout=2)
        for conn in accepted:
            conn.close()
        server.close()


def test_tcp_connect_to_a_public_address_is_blocked(guard):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(OSError) as exc:
            sock.connect(("192.0.2.10", 443))
        assert exc.value.errno == errno.ENETUNREACH
        assert sock.connect_ex(("198.51.100.20", 25)) == errno.ENETUNREACH
    finally:
        sock.close()


def test_dns_lookups_of_public_names_are_blocked(guard):
    with pytest.raises(socket.gaierror):
        socket.getaddrinfo("mail.example.com", 443)
    with pytest.raises(socket.gaierror):
        socket.gethostbyname("smtp.example.com")
    with pytest.raises(socket.gaierror):
        socket.gethostbyname_ex("imap.example.com")
    with pytest.raises(socket.herror):
        socket.gethostbyaddr("203.0.113.7")


def test_udp_datagrams_to_a_public_address_are_blocked(guard):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        with pytest.raises(OSError):
            sock.sendto(b"x", ("198.51.100.53", 53))
        with pytest.raises(OSError):
            sock.sendto(b"x", 0, ("198.51.100.53", 53))
    finally:
        sock.close()


def test_literal_ip_lookup_passes_but_connect_still_fails(guard):
    # getaddrinfo on a literal makes no DNS query, so it is allowed
    assert socket.getaddrinfo("192.0.2.10", 443)
    with pytest.raises(OSError):
        socket.create_connection(("192.0.2.10", 443), timeout=1)


def test_loopback_stays_reachable(guard, loopback_server):
    with socket.create_connection(loopback_server, timeout=2):
        pass


def test_the_database_host_name_stays_resolvable(guard):
    # The name is allowed; whether it resolves is up to the resolver.
    assert network_guard._lookup_allowed("db.demo.test")
    assert network_guard._lookup_allowed("DB.demo.test.")
    assert not network_guard._lookup_allowed("mail.example.com")


def test_http_clients_cannot_reach_mailcow(guard):
    with pytest.raises(httpx.ConnectError):
        httpx.get("https://mail.example.com/api/v1/get/status/containers", timeout=2)

    async def fetch():
        async with httpx.AsyncClient(timeout=2) as client:
            await client.get("https://192.0.2.10/")

    with pytest.raises(httpx.ConnectError):
        asyncio.run(fetch())


def test_asyncio_connections_are_blocked(guard):
    async def connect():
        await asyncio.open_connection("203.0.113.9", 993)

    with pytest.raises(OSError):
        asyncio.run(connect())


def test_smtp_cannot_connect(guard):
    with pytest.raises(OSError):
        smtplib.SMTP("smtp.example.com", 587, timeout=2)


def test_uninstall_restores_the_socket_module():
    original = socket.getaddrinfo
    network_guard.install()
    assert socket.getaddrinfo is not original
    network_guard.uninstall()
    assert socket.getaddrinfo is original
