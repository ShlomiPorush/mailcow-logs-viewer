"""When mailcow keeps failing, callers get MailcowAPIError, never tenacity's RetryError.

The retry decorators used to raise RetryError after the third try, so every
`except MailcowAPIError` around a call was skipped and the request ended in
a 500. A read that fails must also not pass for an empty answer: an empty
transport list turns off blacklist monitoring, an empty container list shows
every container as stopped. Only three reads have a deliberate answer for
"mailcow did not answer": test_connection, get_fail2ban and get_status_host_ip.
"""
import asyncio

import httpx
import pytest

from app import mailcow_api as mod
from app.mailcow_api import MailcowAPIError
from tests.test_mailcow_api_recovery import server  # noqa: F401  (the fake mailcow)

READS = [
    ("get_postfix_logs_page", (), {"page_size": 10, "offset": 0}),
    ("get_rspamd_logs_page", (), {"page_size": 10, "offset": 0}),
    ("get_raw_logs_range", ("postfix", 1, 10), {}),
    ("get_netfilter_logs", (), {}),
    ("get_queue", (), {}),
    ("get_quarantine", (), {}),
    ("get_status_containers", (), {}),
    ("get_status_vmail", (), {}),
    ("get_status_version", (), {}),
    ("get_domains", (), {}),
    ("get_active_domains", (), {}),
    ("get_alias_domain_map", (), {}),
    ("get_mailboxes", (), {}),
    ("get_aliases", (), {}),
    ("get_dkim", ("example.com",), {}),
    ("get_transports", (), {}),
    ("get_relayhosts", (), {}),
    ("get_app_passwords", ("user@example.com",), {}),
    ("get_rl_domain", ("example.com",), {}),
]

WRITES = [
    ("edit_queue", (["ABC"], "flush"), {}),
    ("delete_queue", (["ABC"],), {}),
    ("edit_mailbox", ("user@example.com", {"smtp_access": "0"}), {}),
    ("edit_fail2ban", ({"ban_time": 600, "manage_external": "0"},), {}),
    ("unban_fail2ban", ("192.0.2.1",), {}),
    ("release_quarantine", (["1"],), {}),
    ("delete_quarantine", (["1"],), {}),
    ("edit_rl_domain", ("example.com", 10, "m"), {}),
    ("delete_rl_hash", ("RLabc",), {}),
]


@pytest.fixture()
def failing(server, monkeypatch):  # noqa: F811
    server["answer"] = lambda request: httpx.Response(500, text="mailcow is down")
    monkeypatch.setattr(mod.MailcowAPI._make_rw_request.retry, "wait", lambda *a, **k: 0)
    return server


def _call(name, args, kwargs):
    async def go():
        api = mod.MailcowAPI()
        api.headers_rw = {"X-API-Key": "rw", "Content-Type": "application/json"}
        try:
            return await getattr(api, name)(*args, **kwargs)
        finally:
            await api.aclose()
    return asyncio.run(go())


@pytest.mark.parametrize("name,args,kwargs", READS + WRITES, ids=[r[0] for r in READS + WRITES])
def test_a_call_raises_mailcow_api_error_after_the_tries(failing, name, args, kwargs):
    with pytest.raises(MailcowAPIError) as exc:
        _call(name, args, kwargs)
    assert "500" in str(exc.value)
    assert len(failing["requests"]) == 3


@pytest.mark.parametrize("name,expected", [
    ("test_connection", False),
    ("get_fail2ban", None),
    ("get_status_host_ip", None),
])
def test_these_reads_answer_that_mailcow_did_not_answer(failing, name, expected):
    assert _call(name, (), {}) is expected


def test_a_missing_read_write_key_is_named(failing):
    async def go():
        api = mod.MailcowAPI()
        api.headers_rw = None
        try:
            await api.delete_queue(["ABC"])
        finally:
            await api.aclose()
    with pytest.raises(MailcowAPIError, match="MAILCOW_API_KEY_RW"):
        asyncio.run(go())


# ---------- what the browser is told ----------

def _no_mailcow(*args, **kwargs):
    raise MailcowAPIError("API returned status 500")


def _endpoints():
    from app.routers import domains, logs, status
    return [
        ("get_queue", logs.get_queue, ()),
        ("get_quarantine", logs.get_quarantine, ()),
        ("get_domains", domains.get_all_domains_with_dns, ()),
        ("get_status_containers", status.get_containers_status, ()),
        ("get_status_vmail", status.get_storage_status, ()),
        ("get_domains", status.get_mailcow_info, ()),
    ]


@pytest.fixture()
def no_debug(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "debug", False)


@pytest.mark.parametrize("index", range(6))
def test_a_page_says_mailcow_did_not_answer(monkeypatch, no_debug, index):
    from fastapi import HTTPException
    name, endpoint, args = _endpoints()[index]
    for read in ("get_domains", "get_mailboxes", "get_aliases", name):
        monkeypatch.setattr(mod.mailcow_api, read, _no_mailcow)
    with pytest.raises(HTTPException) as exc:
        asyncio.run(endpoint(*args))
    assert exc.value.status_code == 502
    assert exc.value.detail == "mailcow did not answer. Try again in a moment."


def test_other_errors_stay_private(no_debug):
    from app.utils import internal_error
    assert internal_error(ValueError("secret")).detail == "Internal server error"


def test_a_mailcow_error_no_route_caught_is_still_a_mailcow_answer(no_debug):
    import json
    from app.main import mailcow_exception_handler
    response = asyncio.run(mailcow_exception_handler(None, MailcowAPIError("API returned status 500")))
    assert response.status_code == 502
    assert json.loads(response.body) == {"detail": "mailcow did not answer. Try again in a moment."}


def test_local_domains_stay_as_they_were_when_mailcow_fails(monkeypatch):
    """A failed domain read must not leave only the alias domains as local."""
    from app import scheduler

    async def aliases():
        return {"alias.example": "example.com"}

    monkeypatch.setattr(scheduler.mailcow_api, "get_domains", _no_mailcow_async)
    monkeypatch.setattr(scheduler.mailcow_api, "get_alias_domain_map", aliases)
    cached = []
    monkeypatch.setattr(scheduler, "set_cached_active_domains", cached.append)
    monkeypatch.setattr(scheduler, "update_job_status", lambda *a, **k: None)
    assert asyncio.run(scheduler.sync_local_domains()) is not True
    assert cached == []


async def _no_mailcow_async(*args, **kwargs):
    raise MailcowAPIError("API returned status 500")
