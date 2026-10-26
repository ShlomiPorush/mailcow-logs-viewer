"""A write to mailcow is sent again only when it cannot have reached mailcow.

mailcow releases a quarantined message by sending it and then deleting it, and
keeps working after the app stops waiting. A write retried after a timeout, a
dropped answer or a 5xx can therefore run twice: a released message reached
its recipient twice. Now a write is retried only when the connection was never
made; any other failure is either a definite refusal (4xx) or an outcome
mailcow did not confirm, which the page is told to check before trying again.
"""
import asyncio
import time

import httpx
import pytest

from app import mailcow_api as mod
from app.mailcow_api import MailcowAPIError, MailcowWriteUnknownError

CHECK_FIRST = "mailcow did not confirm the change. It may still be running. Check the result before trying again."


@pytest.fixture()
def mailcow(monkeypatch):
    """A fake mailcow. `answer` decides each attempt: a response, or an exception.
    `attempts` counts every try, `reached` the ones mailcow received."""
    state = {"answer": lambda request: httpx.Response(200, json=[{"type": "success", "msg": ["ok"]}]),
             "attempts": 0, "reached": []}

    def handler(request):
        state["attempts"] += 1
        return state["answer"](request)

    real_client = httpx.AsyncClient

    class FakeClient(real_client):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(mod.httpx, "AsyncClient", FakeClient)
    monkeypatch.setattr(mod.MailcowAPI._rw_attempt.retry, "wait", lambda *a, **k: 0)
    return state


def _reached(state, then):
    """mailcow gets the request and does the work; then `then` happens."""
    def answer(request):
        state["reached"].append(request)
        return then(request)
    return answer


def _raise(error):
    def then(request):
        raise error("no answer", request=request)
    return then


def _release(api_key=True):
    async def go():
        api = mod.MailcowAPI()
        api.headers_rw = {"X-API-Key": "rw", "Content-Type": "application/json"} if api_key else None
        try:
            return await api.release_quarantine(["1", "2"])
        finally:
            await api.aclose()
    return asyncio.run(go())


def test_a_connection_never_made_is_tried_again(mailcow):
    failures = {"left": 2}

    def answer(request):
        if failures["left"]:
            failures["left"] -= 1
            raise httpx.ConnectError("refused", request=request)
        mailcow["reached"].append(request)
        return httpx.Response(200, json=[{"type": "success", "msg": ["item_released", "1"]}])
    mailcow["answer"] = answer
    assert _release()[0]["type"] == "success"
    assert (mailcow["attempts"], len(mailcow["reached"])) == (3, 1)


def test_a_connection_never_made_fails_as_mailcow_not_answering(mailcow):
    def answer(request):
        raise httpx.ConnectTimeout("no route", request=request)
    mailcow["answer"] = answer
    with pytest.raises(MailcowAPIError) as raised:
        _release()
    assert not isinstance(raised.value, MailcowWriteUnknownError)
    assert (mailcow["attempts"], len(mailcow["reached"])) == (3, 0)


@pytest.mark.parametrize("then", [
    _raise(httpx.ReadTimeout),
    _raise(httpx.RemoteProtocolError),
    _raise(httpx.ReadError),
    lambda request: httpx.Response(500, text="PHP fatal error"),
    lambda request: httpx.Response(504, text="gateway timeout"),
    lambda request: httpx.Response(200, text="<html>", headers={"content-type": "application/json"}),
], ids=["read-timeout", "dropped-after-sending", "read-error", "500", "504", "not-json"])
def test_a_write_mailcow_received_is_sent_once(mailcow, then):
    """A batch release slower than the timeout, or an answer that is lost or
    unreadable: mailcow may have sent the messages, so they are not sent again."""
    mailcow["answer"] = _reached(mailcow, then)
    with pytest.raises(MailcowWriteUnknownError) as raised:
        _release()
    assert str(raised.value) == CHECK_FIRST
    assert len(mailcow["reached"]) == 1 and mailcow["attempts"] == 1


@pytest.mark.parametrize("status", [400, 404, 422])
def test_a_write_mailcow_refused_is_not_tried_again(mailcow, status):
    mailcow["answer"] = _reached(mailcow, lambda request: httpx.Response(status, text="bad request"))
    with pytest.raises(MailcowAPIError) as raised:
        _release()
    assert not isinstance(raised.value, MailcowWriteUnknownError)
    assert mailcow["attempts"] == 1


def test_a_missing_read_write_key_fails_at_once(monkeypatch):
    start = time.monotonic()
    with pytest.raises(MailcowAPIError, match="MAILCOW_API_KEY_RW"):
        _release(api_key=False)
    assert time.monotonic() - start < 1


# ---------- what the page is told ----------

def test_the_page_is_told_to_check_first():
    from app.routers import rate_limits
    from app.utils import internal_error
    unknown = MailcowWriteUnknownError("read timeout")
    assert (internal_error(unknown).status_code, internal_error(unknown).detail) == (502, CHECK_FIRST)
    assert rate_limits._write_failed(unknown, "mailcow did not apply the limit").detail == CHECK_FIRST
    # A definite failure keeps its own text
    assert rate_limits._write_failed(MailcowAPIError("400"), "mailcow did not apply the limit").detail \
        == "mailcow did not apply the limit"


def test_an_unban_mailcow_did_not_confirm_says_so(monkeypatch):
    import starlette.staticfiles as sf
    real_init = sf.StaticFiles.__init__
    monkeypatch.setattr(sf.StaticFiles, "__init__", lambda s, *a, **k: real_init(s, *a, **{**k, "check_dir": False}))
    from fastapi.testclient import TestClient
    from app.config import settings
    from app.main import app
    for key in ("auth_enabled", "basic_auth_enabled", "oauth2_enabled"):
        monkeypatch.setattr(settings._inner, key, False)

    async def bans():
        return {"active_bans": [{"network": "198.51.100.7/32"}], "blacklist": ""}

    async def unban(networks):
        raise MailcowWriteUnknownError("read timeout")
    monkeypatch.setattr(mod.mailcow_api, "headers_rw", {"X-API-Key": "rw"})
    monkeypatch.setattr(mod.mailcow_api, "get_fail2ban", bans)
    monkeypatch.setattr(mod.mailcow_api, "unban_fail2ban", unban)
    r = TestClient(app, raise_server_exceptions=False).post("/api/fail2ban/unban", json={"ip": "198.51.100.7"})
    assert r.status_code == 502 and r.json()["detail"] == CHECK_FIRST


# ---------- NaN and Infinity are not JSON ----------

def test_an_answer_with_nan_is_not_taken_as_json(mailcow, monkeypatch):
    """Python's parser takes NaN and Infinity, mailcow cannot send them, and an
    answer that passed them on failed when sent to the browser."""
    monkeypatch.setattr(mod.MailcowAPI._make_request.retry, "wait", lambda *a, **k: 0)
    body = b'[{"queue_id": "A", "message_size": Infinity}]'
    mailcow["answer"] = lambda request: httpx.Response(200, content=body, headers={"content-type": "application/json"})

    async def read():
        api = mod.MailcowAPI()
        try:
            return await api.get_queue()
        finally:
            await api.aclose()
    with pytest.raises(MailcowAPIError):
        asyncio.run(read())
    mailcow["answer"] = _reached(mailcow, lambda request: httpx.Response(
        200, content=b'[{"type": "success", "msg": NaN}]', headers={"content-type": "application/json"}))
    with pytest.raises(MailcowWriteUnknownError):
        _release()
