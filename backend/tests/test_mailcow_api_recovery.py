"""The mailcow client recovers when mailcow refuses or drops it.

On DEV mailcow dropped the connections, and from then on every call of the
running app got 403 for over half an hour, while a new process with the same
key got 200. Nothing a call leaves behind may decide the next one: mailcow's
session cookie is not kept, and a client mailcow refused or dropped is
replaced. And when mailcow keeps failing, Fail2ban's answer is None, so the
Security page loads without it instead of failing.
"""
import asyncio

import httpx
import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app import mailcow_api as mod  # noqa: E402


@pytest.fixture()
def server(monkeypatch):
    """A fake mailcow; `answer` decides each response, `clients` counts the clients made."""
    state = {"answer": lambda request: httpx.Response(200, json=[{"ok": True}]), "clients": 0, "requests": []}

    def handler(request):
        state["requests"].append(request)
        return state["answer"](request)

    real_client = httpx.AsyncClient

    class FakeClient(real_client):
        def __init__(self, *args, **kwargs):
            state["clients"] += 1
            kwargs["transport"] = httpx.MockTransport(handler)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(mod.httpx, "AsyncClient", FakeClient)
    # No waiting between the three tries
    monkeypatch.setattr(mod.MailcowAPI._make_request.retry, "wait", lambda *a, **k: 0)
    return state


def test_mailcows_session_cookie_is_not_sent_back(server):
    def answer(request):
        if "MCSESSID" in request.headers.get("cookie", ""):
            return httpx.Response(403)
        return httpx.Response(200, json=[{"ok": True}], headers={"set-cookie": "MCSESSID=abc; path=/; HttpOnly"})
    server["answer"] = answer

    async def scenario():
        api = mod.MailcowAPI()
        first = await api._make_request("/api/v1/get/fail2ban")
        second = await api._make_request("/api/v1/get/fail2ban")
        await api.aclose()
        return first, second

    assert asyncio.run(scenario()) == ([{"ok": True}], [{"ok": True}])
    assert all("cookie" not in r.headers for r in server["requests"])


def test_a_refused_client_is_replaced_before_the_next_try(server):
    refused = {"left": 1}

    def answer(request):
        if refused["left"]:
            refused["left"] -= 1
            return httpx.Response(403)
        return httpx.Response(200, json=[{"ok": True}])
    server["answer"] = answer

    async def scenario():
        api = mod.MailcowAPI()
        data = await api._make_request("/api/v1/get/logs/postfix/1")
        await api.aclose()
        return data

    assert asyncio.run(scenario()) == [{"ok": True}]
    # The 403 retired the first client; the retry came on a new one
    assert server["clients"] == 2


def test_a_dropped_connection_replaces_the_client(server):
    dropped = {"left": 1}

    def answer(request):
        if dropped["left"]:
            dropped["left"] -= 1
            raise httpx.RemoteProtocolError("Server disconnected without sending a response.", request=request)
        return httpx.Response(200, json=[{"ok": True}])
    server["answer"] = answer

    async def scenario():
        api = mod.MailcowAPI()
        data = await api._make_request("/api/v1/get/logs/postfix/1")
        await api.aclose()
        return data

    assert asyncio.run(scenario()) == [{"ok": True}]
    assert server["clients"] == 2


def test_a_good_answer_keeps_the_client(server):
    async def scenario():
        api = mod.MailcowAPI()
        for _ in range(3):
            await api._make_request("/api/v1/get/domain/all")
        await api.aclose()

    asyncio.run(scenario())
    assert server["clients"] == 1


def test_fail2ban_answers_none_when_mailcow_fails_every_try(server):
    server["answer"] = lambda request: httpx.Response(403)

    async def scenario():
        api = mod.MailcowAPI()
        try:
            return await api.get_fail2ban()
        finally:
            await api.aclose()

    # So the Security page loads without Fail2ban instead of failing
    assert asyncio.run(scenario()) is None
    assert len(server["requests"]) == 3
