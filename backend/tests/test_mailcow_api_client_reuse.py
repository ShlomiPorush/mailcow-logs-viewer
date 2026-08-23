"""Issue #84: excessive DNS queries for the mailcow host.

Every API call used to open (and close) its own httpx.AsyncClient, so
every single request meant a fresh TCP connection and a fresh A/AAAA
lookup of the mailcow server. With polling jobs running every 30-60
seconds this produced hundreds of DNS queries per 10 minutes.

The client must be created once per event loop and reused across
requests, with keep-alive long enough to bridge the polling intervals.
"""
import asyncio

import httpx
import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app import mailcow_api as mod  # noqa: E402


@pytest.fixture()
def counting_client(monkeypatch):
    """Count AsyncClient instantiations and serve canned responses."""
    created = {"count": 0, "limits": []}

    def handler(request):
        return httpx.Response(200, json={"ok": True, "path": request.url.path})

    real_client = httpx.AsyncClient

    class CountingClient(real_client):
        def __init__(self, *args, **kwargs):
            created["count"] += 1
            created["limits"].append(kwargs.get("limits"))
            kwargs["transport"] = httpx.MockTransport(handler)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(mod.httpx, "AsyncClient", CountingClient)
    return created


def _fresh_api():
    return mod.MailcowAPI()


def test_client_is_reused_across_requests(counting_client):
    async def scenario():
        api = _fresh_api()
        await api._make_request("/api/v1/get/logs/postfix/1")
        await api._make_request("/api/v1/get/logs/rspamd-history/1")
        await api._make_request("/api/v1/get/domain/all")
        await api.aclose()

    asyncio.run(scenario())
    assert counting_client["count"] == 1, (
        f"3 requests created {counting_client['count']} clients - each new "
        "client costs a TCP connect plus a DNS lookup of the mailcow host (#84)"
    )


def test_each_event_loop_gets_its_own_client(counting_client):
    """Manually triggered jobs run in their own event loop; an httpx client
    must never be shared across loops."""
    api = _fresh_api()

    async def one_call():
        await api._make_request("/api/v1/get/status/containers")

    asyncio.run(one_call())
    asyncio.run(one_call())
    assert counting_client["count"] == 2


def test_reload_config_recreates_the_client(counting_client, monkeypatch):
    async def scenario():
        api = _fresh_api()
        await api._make_request("/api/v1/get/logs/postfix/1")
        monkeypatch.setattr(mod.settings._inner, "mailcow_api_timeout", api.timeout + 5)
        api.reload_config()
        await asyncio.sleep(0)  # let the scheduled aclose of the old client run
        await api._make_request("/api/v1/get/logs/postfix/1")
        await api.aclose()

    asyncio.run(scenario())
    assert counting_client["count"] == 2


def test_keepalive_bridges_the_polling_interval(counting_client):
    """The pool keeps idle connections long enough for the 30-60s pollers."""
    async def scenario():
        api = _fresh_api()
        api._get_client()
        await api.aclose()

    asyncio.run(scenario())
    limits = counting_client["limits"][0]
    # httpx defaults to 5s, which dies between polls and forces a fresh
    # connection (and DNS lookup) on every cycle
    assert limits is not None and limits.keepalive_expiry >= 120
