import asyncio

import httpx
import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app import mailcow_api as mod  # noqa: E402


@pytest.fixture()
def server(monkeypatch):
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

    assert asyncio.run(scenario()) is None
    assert len(server["requests"]) == 3
