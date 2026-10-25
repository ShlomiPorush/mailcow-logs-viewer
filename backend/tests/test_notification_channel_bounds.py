"""Sending to a notification channel is bounded in time and in what it reads.

The send read the channel server's whole answer with only a per-step
timeout, so a server that answered slowly or without end held the notifying
worker thread and buffered all of it. The send now has one deadline for all
of it, including the name lookup, reads at most a small piece of an error
answer and none of a success or redirect answer, and refuses to decompress.
"""
import contextlib
import gc
import logging
import socket
import socketserver
import threading
import time

import httpx
import pytest

from app.services import notification_channels as nc

TOO_SLOW = "The server took too long to answer."


def _read_request(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            return
        data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1])
    while len(body) < length:
        chunk = sock.recv(4096)
        if not chunk:
            return
        body += chunk


@contextlib.contextmanager
def raw_server(answer):
    """A local server whose answer() writes raw bytes to the socket. Every
    answer ends by itself within a few seconds, so a client that waits for
    all of it (the old code) fails the test instead of hanging the suite."""
    state = {"aborted": False, "done": threading.Event()}

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(10)
            try:
                _read_request(self.request)
                answer(self.request)
            except OSError:
                state["aborted"] = True
            finally:
                state["done"].set()

    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", state
    finally:
        server.shutdown()
        server.server_close()


def _send(base):
    config = {"webhook_url": f"{base}/services/T0/B0/SECRETPATH"}
    started = time.monotonic()
    result = nc.send_to_config("slack", config, "Subject", "Body")
    return result, time.monotonic() - started


def _endless_body(sock):
    sock.sendall(b"HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n")
    piece = b"x" * 65536
    for _ in range(1024):   # 64 MiB at most
        sock.sendall(piece)


def test_an_endless_error_answer_is_cut_at_the_cap():
    with raw_server(_endless_body) as (base, state):
        (ok, error), elapsed = _send(base)
        assert state["done"].wait(5)
    assert ok is False
    assert error == "HTTP 500: " + "x" * 200
    assert elapsed < 3
    # The client stopped reading and closed the connection long before the end
    assert state["aborted"]


def _trickle(head, then, seconds=4):
    def answer(sock):
        sock.sendall(head)
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            sock.sendall(then)
            time.sleep(0.1)
        sock.sendall(b"\r\n\r\n" if b"X-Slow" in head else b"")
    return answer


@pytest.mark.parametrize("answer", [
    _trickle(b"HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n", b"x"),
    _trickle(b"HTTP/1.1 500 Internal Server Error\r\nX-Slow: ", b"y"),
], ids=["body", "headers"])
def test_a_trickling_answer_stops_at_the_deadline(monkeypatch, answer):
    monkeypatch.setattr(nc, "_TOTAL_SECONDS", 1, raising=False)
    with raw_server(answer) as (base, _state):
        (ok, error), elapsed = _send(base)
    assert (ok, error) == (False, TOO_SLOW)
    assert elapsed < 2.5


def test_a_silent_server_is_reported_as_too_slow(monkeypatch):
    monkeypatch.setattr(nc, "_TIMEOUT_SECONDS", 0.5)
    with raw_server(lambda sock: time.sleep(3)) as (base, _state):
        (ok, error), elapsed = _send(base)
    assert (ok, error) == (False, TOO_SLOW)
    assert elapsed < 2


def test_a_stuck_name_lookup_stops_at_the_deadline(monkeypatch):
    monkeypatch.setattr(nc, "_TOTAL_SECONDS", 1, raising=False)
    release = threading.Event()
    real = socket.getaddrinfo

    def stuck(host, *args, **kwargs):
        if host in ("slow-dns.test", b"slow-dns.test"):   # anyio passes it encoded
            release.wait(5)
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        return real(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", stuck)
    try:
        (ok, error), elapsed = _send("http://slow-dns.test:8080")
    finally:
        release.set()
    assert (ok, error) == (False, TOO_SLOW)
    assert elapsed < 2.5


def _answer(status, body=b"", content_type="text/plain"):
    def answer(sock):
        sock.sendall(f"HTTP/1.1 {status} X\r\nContent-Type: {content_type}\r\n"
                     f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)
    return answer


def test_a_normal_success():
    with raw_server(_answer(200, b"ok")) as (base, _state):
        (ok, error), _elapsed = _send(base)
    assert (ok, error) == (True, "")


def test_a_normal_error_keeps_its_message_without_secrets():
    body = b'{"error": "no such hook /services/T0/B0/SECRETPATH"}'
    with raw_server(_answer(400, body, "application/json")) as (base, _state):
        (ok, error), _elapsed = _send(base)
    assert ok is False
    assert error.startswith('HTTP 400: {"error": "no such hook ')
    assert "SECRET" not in error


@pytest.mark.parametrize("content_type, body, shown", [
    ("text/plain; charset=iso-8859-1", "café".encode("latin-1"), "café"),
    ("text/plain", "café".encode("utf-8"), "café"),
    ("text/plain; charset=x-no-such-charset", "café".encode("utf-8"), "café"),
], ids=["declared", "missing", "unknown"])
def test_the_error_text_uses_the_declared_charset_or_utf8(content_type, body, shown):
    with raw_server(_answer(403, body, content_type)) as (base, _state):
        (_ok, error), _elapsed = _send(base)
    assert error == f"HTTP 403: {shown}"


# ── What is read, through httpx's own transport ─────────────────────────────

class CountingStream(httpx.AsyncByteStream):
    def __init__(self, chunk=b"z" * 512, limit=10_000):
        self.chunk, self.limit = chunk, limit
        self.pulled, self.closed = 0, False

    async def __aiter__(self):
        while self.pulled < self.limit:
            self.pulled += 1
            yield self.chunk

    async def aclose(self):
        self.closed = True


@pytest.fixture
def transport(monkeypatch):
    """Answer every send with the response the test sets; record requests."""
    state = {"requests": [], "clients": []}
    real_client = httpx.AsyncClient

    class FakeClient(real_client):
        def __init__(self, *args, **kwargs):
            state["clients"].append(kwargs)

            def handler(request):
                state["requests"].append(request)
                return state["response"]()
            kwargs["transport"] = httpx.MockTransport(handler)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
    return state


@pytest.mark.parametrize("status", [200, 204, 307])
def test_a_success_or_redirect_answer_is_not_read(transport, status):
    stream = CountingStream()
    transport["response"] = lambda: httpx.Response(status, stream=stream)
    nc.send_to_config("slack", {"webhook_url": "https://hooks.example.com/x"}, "S", "M")
    assert stream.pulled == 0
    assert stream.closed


def test_an_endless_error_answer_is_read_only_to_the_cap(transport):
    stream = CountingStream()
    transport["response"] = lambda: httpx.Response(500, stream=stream)
    ok, error = nc.send_to_config("slack", {"webhook_url": "https://hooks.example.com/x"}, "S", "M")
    assert error == "HTTP 500: " + "z" * 200
    assert stream.pulled == nc._MAX_ERROR_BYTES // 512
    assert stream.closed


def test_a_cut_answer_leaves_nothing_pending(transport, caplog):
    """Stopping early leaves httpx's inner stream generators to be closed by
    tasks of their own; the send's loop must run them, not log them as
    destroyed while pending."""
    transport["response"] = lambda: httpx.Response(500, stream=CountingStream())
    with caplog.at_level(logging.ERROR, logger="asyncio"):
        nc.send_to_config("slack", {"webhook_url": "https://hooks.example.com/x"}, "S", "M")
        gc.collect()
    assert [r.getMessage() for r in caplog.records if r.name == "asyncio"] == []


def test_a_compressed_error_answer_is_not_decoded(transport):
    stream = CountingStream()
    transport["response"] = lambda: httpx.Response(500, headers={"Content-Encoding": "gzip"}, stream=stream)
    ok, error = nc.send_to_config("slack", {"webhook_url": "https://hooks.example.com/x"}, "S", "M")
    assert (ok, error) == (False, "HTTP 500: ")
    assert stream.pulled == 0
    assert stream.closed


def test_the_send_asks_for_an_uncompressed_answer(transport):
    transport["response"] = lambda: httpx.Response(200)
    config = {"url": "https://hooks.example.com/hook", "auth_header": "Bearer t"}
    assert nc.send_to_config("webhook", config, "S", "M") == (True, "")
    request = transport["requests"][0]
    assert request.headers["Accept-Encoding"] == "identity"
    assert request.headers["Authorization"] == "Bearer t"


def test_ntfy_sends_the_text_as_the_body(transport):
    transport["response"] = lambda: httpx.Response(200)
    assert nc.send_to_config("ntfy", {"server_url": "https://ntfy.example.com", "topic": "alerts"},
                             "Subject", "Body") == (True, "")
    request = transport["requests"][0]
    assert request.url.params["title"] == "Subject"
    assert request.content == b"Body"


@pytest.mark.parametrize("env, expected", [
    ({}, None),
    ({"REQUESTS_CA_BUNDLE": "/certs/ca.pem"}, {"cafile": "/certs/ca.pem"}),
    ({"CURL_CA_BUNDLE": "/certs/curl.pem"}, {"cafile": "/certs/curl.pem"}),
    ({"REQUESTS_CA_BUNDLE": "/certs/ca.pem", "CURL_CA_BUNDLE": "/certs/curl.pem"}, {"cafile": "/certs/ca.pem"}),
    ({"REQUESTS_CA_BUNDLE": "/certs"}, {"capath": "/certs"}),
], ids=["default", "requests", "curl", "requests-first", "directory"])
def test_the_ca_bundle_settings_of_requests_still_apply(monkeypatch, transport, env, expected):
    for name in ("REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(nc.os.path, "isdir", lambda path: path == "/certs")
    made = []
    monkeypatch.setattr(nc.ssl, "create_default_context", lambda **kw: made.append(kw) or nc.ssl.SSLContext(nc.ssl.PROTOCOL_TLS_CLIENT))
    transport["response"] = lambda: httpx.Response(200)
    assert nc.send_to_config("slack", {"webhook_url": "https://hooks.example.com/x"}, "S", "M") == (True, "")
    verify = transport["clients"][0]["verify"]
    if expected is None:
        assert verify is True and made == []
    else:
        assert made == [expected] and isinstance(verify, nc.ssl.SSLContext)
