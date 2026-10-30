"""
A Read-Write key that mailcow refuses fails at once, without retries, and the
page is told what to fix instead of "Internal server error" (issue #384).
"""
import asyncio

import httpx
import pytest
from fastapi import HTTPException
from tenacity import wait_none

from app.mailcow_api import MailcowAPI, MailcowRwKeyError
from app.routers import logs, rate_limits


@pytest.fixture
def mailcow(monkeypatch):
    """The shared client, answering every request with the status in ``answer``."""
    from app.mailcow_api import mailcow_api
    answer = {"status": 200}
    requests = []

    def handle(request):
        requests.append(request)
        return httpx.Response(answer["status"], json=[{"type": "success", "msg": "ok"}])

    client = httpx.AsyncClient(transport=httpx.MockTransport(handle))
    monkeypatch.setattr(mailcow_api, "_get_client", lambda: client)
    monkeypatch.setattr(mailcow_api, "headers_rw", {"X-API-Key": "rw-key", "Content-Type": "application/json"})
    monkeypatch.setattr(MailcowAPI._rw_attempt.retry, "wait", wait_none())
    return answer, requests


@pytest.mark.parametrize("status, code", [(401, "rejected"), (403, "read_only")])
def test_a_refused_key_is_not_retried(mailcow, status, code):
    from app.mailcow_api import mailcow_api
    answer, requests = mailcow
    answer["status"] = status
    with pytest.raises(MailcowRwKeyError) as raised:
        asyncio.run(mailcow_api.learnspam_quarantine(["1"]))
    assert raised.value.code == code
    assert len(requests) == 1


def test_a_500_is_not_retried_either(mailcow):
    """mailcow received the write and may have made it (tests/test_mailcow_write_retry.py)."""
    from app.mailcow_api import MailcowWriteUnknownError, mailcow_api
    answer, requests = mailcow
    answer["status"] = 500
    with pytest.raises(MailcowWriteUnknownError):
        asyncio.run(mailcow_api.learnspam_quarantine(["1"]))
    assert len(requests) == 1


class _Request:
    def __init__(self, body):
        self._body = body

    async def json(self):
        return self._body


@pytest.mark.parametrize("action", ["release", "delete", "learnham", "learnspam"])
def test_quarantine_actions_say_the_key_was_rejected(mailcow, action):
    answer, _ = mailcow
    answer["status"] = 401
    route = getattr(logs, f"{action}_quarantine")
    with pytest.raises(HTTPException) as raised:
        asyncio.run(route(_Request({"items": ["1"]})))
    assert raised.value.status_code == 502
    assert raised.value.detail == MailcowRwKeyError.MESSAGES["rejected"]


def test_rate_limit_writes_say_the_key_is_read_only():
    error = rate_limits._write_failed(MailcowRwKeyError("read_only"), "generic")
    assert (error.status_code, error.detail) == (502, MailcowRwKeyError.MESSAGES["read_only"])
    from app.mailcow_api import MailcowAPIError
    assert rate_limits._write_failed(MailcowAPIError("boom"), "generic").detail == "generic"


def test_unban_says_the_key_was_rejected(mailcow, monkeypatch):
    from app.mailcow_api import mailcow_api
    answer, _ = mailcow
    answer["status"] = 401

    async def banned():  # the read-only key still reads the ban
        return {"active_bans": [{"network": "192.0.2.1/32", "ip": "192.0.2.1"}]}

    monkeypatch.setattr(mailcow_api, "get_fail2ban", banned)
    with pytest.raises(HTTPException) as raised:
        asyncio.run(logs.unban_fail2ban(_Request({"ip": "192.0.2.1"})))
    assert raised.value.status_code == 502
    assert raised.value.detail == MailcowRwKeyError.MESSAGES["rejected"]
