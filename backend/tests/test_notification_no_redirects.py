"""Notification channels do not follow redirects.

A redirect would send the alert (and for some channels the token in the URL or
the Authorization header) to wherever the first server points. A 3xx answer is
now a failed send with a short message saying so, for every channel type and
for the Test button, which uses the same send_to_config.
"""
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from app.services import notification_channels as nc


@pytest.fixture
def redirecting_server():
    hits = []

    class Handler(BaseHTTPRequestHandler):
        def _answer(self):
            hits.append(self.path)
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                self.rfile.read(length)
            if self.path.startswith("/landing"):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")
                return
            self.send_response(307)
            self.send_header("Location", "/landing")
            self.end_headers()

        do_POST = _answer
        do_GET = _answer

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", hits
    finally:
        server.shutdown()
        server.server_close()


CONFIGS = {
    "slack": lambda base: {"webhook_url": f"{base}/services/T0/B0/SECRETPATH"},
    "discord": lambda base: {"webhook_url": f"{base}/api/webhooks/1/SECRETPATH"},
    "ntfy": lambda base: {"server_url": base, "topic": "alerts", "token": "SECRETTOKEN"},
    "gotify": lambda base: {"server_url": base, "app_token": "SECRETTOKEN"},
    "webhook": lambda base: {"url": f"{base}/hook", "auth_header": "Bearer SECRETTOKEN"},
}


@pytest.mark.parametrize("channel_type", sorted(CONFIGS))
def test_a_redirect_is_reported_and_not_followed(redirecting_server, channel_type):
    base, hits = redirecting_server
    ok, error = nc.send_to_config(channel_type, CONFIGS[channel_type](base), "Subject", "Body")
    assert ok is False
    assert "redirect" in error.lower()
    assert "307" in error
    assert "SECRET" not in error
    assert not any(path.startswith("/landing") for path in hits)


def test_every_send_disables_redirects(monkeypatch):
    """Telegram's URL is fixed, so check the request itself for every type."""
    seen, hits = [], []
    real_client = nc.httpx.AsyncClient

    class FakeClient(real_client):
        def __init__(self, *args, **kwargs):
            seen.append(kwargs.get("follow_redirects"))

            def handler(request):
                hits.append(request.url.path)
                return nc.httpx.Response(307, headers={"Location": "https://elsewhere.example.com/landing"})
            kwargs["transport"] = nc.httpx.MockTransport(handler)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(nc.httpx, "AsyncClient", FakeClient)
    configs = {**{k: v("https://hooks.example.com") for k, v in CONFIGS.items()},
               "telegram": {"bot_token": "123:ABC", "chat_id": "42"}}
    for channel_type, config in configs.items():
        ok, error = nc.send_to_config(channel_type, config, "S", "M")
        assert ok is False and "redirect" in error.lower(), channel_type
    assert seen == [False] * len(configs)
    assert "/landing" not in hits and len(hits) == len(configs)
