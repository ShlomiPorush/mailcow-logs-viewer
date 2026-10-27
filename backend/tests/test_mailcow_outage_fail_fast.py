"""While mailcow cannot be reached, the app fails at once instead of freezing.

On DEV, with mailcow's traffic dropped, every mailcow read waited about 94
seconds (three tries, each waiting for the connection timeout), the browser's
connections filled up and pages that only read the database waited behind
them, and a container started during the outage served nothing for about 96
seconds because startup asked mailcow first. Now a failed connection marks
mailcow's address as unreachable for a moment: requests to it fail locally
with "mailcow cannot be reached", one request then tries again, and startup
does not ask mailcow at all.
"""
import asyncio
import threading
import time
from contextlib import asynccontextmanager, contextmanager
from unittest.mock import AsyncMock, Mock

import httpx
import pytest

from app import config, scheduler
from app import mailcow_api as mod
from app.config import settings
from app.mailcow_api import MailcowAPIError, MailcowUnreachableError, MailcowWriteUnknownError
from app.routers import domains

URL = "https://mail.example.com"
UNREACHABLE = "mailcow cannot be reached. It is tried again within 30 seconds."


@pytest.fixture()
def mailcow(monkeypatch):
    """A fake mailcow. `answer` decides each attempt (a response, an exception,
    or a coroutine for one); `requests` holds every attempt that reached the network."""
    state = {"answer": lambda request: httpx.Response(200, json=[{"ok": True}]),
             "requests": [], "timeouts": []}

    def handler(request):
        state["requests"].append(request)
        return state["answer"](request)

    real_client = httpx.AsyncClient

    class FakeClient(real_client):
        def __init__(self, *args, **kwargs):
            state["timeouts"].append(kwargs.get("timeout"))
            kwargs["transport"] = httpx.MockTransport(handler)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(mod.httpx, "AsyncClient", FakeClient)
    monkeypatch.setattr(mod.MailcowAPI._make_request.retry, "wait", lambda *a, **k: 0)
    monkeypatch.setattr(settings._inner, "mailcow_url", URL)
    return state


@pytest.fixture()
def clock(module_clock):
    """The breaker's clock, moved by hand."""
    now = {"t": 1000.0}
    module_clock(mod, monotonic=lambda: now["t"])
    return now


def _raise(error):
    def answer(request):
        raise error("no connection", request=request)
    return answer


def _api():
    api = mod.MailcowAPI()
    api.base_url = URL
    return api


def _read(api, endpoint="/api/v1/get/logs/postfix/1"):
    return api._make_request(endpoint)


def run(coro):
    return asyncio.run(coro)


async def _closing(api, coro):
    try:
        return await coro
    finally:
        await api.aclose()


# ---------- one failed connection, then local refusals ----------

@pytest.mark.parametrize("error", [httpx.ConnectError, httpx.ConnectTimeout], ids=["connect-error", "connect-timeout"])
def test_an_unreachable_mailcow_is_asked_once_then_refused_locally(mailcow, error):
    mailcow["answer"] = _raise(error)
    api = _api()

    async def scenario():
        with pytest.raises(MailcowAPIError) as first:
            await _read(api)
        assert len(mailcow["requests"]) == 1, "a connection that failed is not tried again"
        assert first.value.transient is True
        for _ in range(3):
            with pytest.raises(MailcowUnreachableError) as refused:
                await _read(api)
            assert str(refused.value) == UNREACHABLE and refused.value.transient is True
        await api.aclose()

    run(scenario())
    assert len(mailcow["requests"]) == 1


def test_the_refusal_is_shown_to_the_page_as_it_is(monkeypatch):
    from app.utils import internal_error
    monkeypatch.setattr(settings._inner, "debug", False)
    error = internal_error(MailcowUnreachableError())
    assert (error.status_code, error.detail) == (502, UNREACHABLE)


def test_a_read_timeout_is_not_tried_again_and_does_not_mark_mailcow_unreachable(mailcow):
    """A slow mailcow (a large log page) is not a missing one."""
    mailcow["answer"] = _raise(httpx.ReadTimeout)
    api = _api()

    async def scenario():
        with pytest.raises(MailcowAPIError) as raised:
            await _read(api)
        assert raised.value.transient is True
        assert len(mailcow["requests"]) == 1, "a timeout tried again only makes the page wait as long again"
        mailcow["answer"] = lambda request: httpx.Response(200, json=[])
        assert await _read(api) == []
        await api.aclose()

    run(scenario())
    assert len(mailcow["requests"]) == 2


def test_a_refused_key_is_still_tried_again_on_a_new_client(mailcow):
    refused = {"left": 1}

    def answer(request):
        if refused["left"]:
            refused["left"] -= 1
            return httpx.Response(403)
        return httpx.Response(200, json=[{"ok": True}])
    mailcow["answer"] = answer
    api = _api()
    assert run(_closing(api, _read(api))) == [{"ok": True}]
    assert len(mailcow["requests"]) == 2 and len(mailcow["timeouts"]) == 2


def test_the_connection_gets_at_most_ten_seconds(mailcow):
    api = _api()
    api.timeout = 30
    run(_closing(api, _read(api)))
    api = _api()
    api.timeout = 5
    run(_closing(api, _read(api)))
    long, short = mailcow["timeouts"]
    assert (long.connect, long.read, long.write, long.pool) == (10, 30, 30, 30)
    assert (short.connect, short.read) == (5, 5)


# ---------- the probe after the pause ----------

def test_after_the_pause_one_request_tries_and_an_answer_clears(mailcow, clock):
    mailcow["answer"] = _raise(httpx.ConnectError)
    api = _api()

    async def scenario():
        with pytest.raises(MailcowAPIError):
            await _read(api)
        clock["t"] += 29
        with pytest.raises(MailcowUnreachableError):
            await _read(api)
        clock["t"] += 2
        mailcow["answer"] = lambda request: httpx.Response(200, json=[])
        assert await _read(api) == []
        assert await _read(api) == []
        await api.aclose()

    run(scenario())
    assert len(mailcow["requests"]) == 3


def test_any_http_answer_counts_as_reached(mailcow, clock):
    mailcow["answer"] = _raise(httpx.ConnectError)
    api = _api()

    async def scenario():
        with pytest.raises(MailcowAPIError):
            await _read(api)
        clock["t"] += 31
        mailcow["answer"] = lambda request: httpx.Response(500)
        with pytest.raises(MailcowAPIError) as raised:
            await _read(api)
        assert not isinstance(raised.value, MailcowUnreachableError) and raised.value.transient is True
        await api.aclose()

    run(scenario())
    # The probe got an answer: the two tries after it went to mailcow as well
    assert len(mailcow["requests"]) == 4


def test_a_failed_probe_starts_a_new_pause(mailcow, clock):
    mailcow["answer"] = _raise(httpx.ConnectError)
    api = _api()

    async def scenario():
        with pytest.raises(MailcowAPIError):
            await _read(api)
        clock["t"] += 31
        with pytest.raises(MailcowAPIError):
            await _read(api)
        with pytest.raises(MailcowUnreachableError):
            await _read(api)
        await api.aclose()

    run(scenario())
    assert len(mailcow["requests"]) == 2


@pytest.mark.parametrize("error", [httpx.ReadTimeout, httpx.RemoteProtocolError], ids=["read-timeout", "dropped"])
def test_a_probe_that_ends_otherwise_lets_the_next_request_try(mailcow, clock, error):
    mailcow["answer"] = _raise(httpx.ConnectError)
    api = _api()

    async def scenario():
        with pytest.raises(MailcowAPIError):
            await _read(api)
        clock["t"] += 31
        mailcow["answer"] = _raise(error)
        with pytest.raises(MailcowAPIError) as raised:
            await _read(api)
        assert not isinstance(raised.value, MailcowUnreachableError)
        before = len(mailcow["requests"])
        mailcow["answer"] = lambda request: httpx.Response(200, json=[])
        assert await _read(api) == []
        assert len(mailcow["requests"]) == before + 1
        await api.aclose()

    run(scenario())


def test_a_cancelled_probe_lets_the_next_request_try(mailcow, clock):
    mailcow["answer"] = _raise(httpx.ConnectError)
    api = _api()

    async def scenario():
        with pytest.raises(MailcowAPIError):
            await _read(api)
        clock["t"] += 31
        started = asyncio.Event()

        async def hang(request):
            started.set()
            await asyncio.sleep(60)
        mailcow["answer"] = hang
        probe = asyncio.create_task(_read(api))
        await started.wait()
        probe.cancel()
        with pytest.raises(asyncio.CancelledError):
            await probe
        mailcow["answer"] = lambda request: httpx.Response(200, json=[])
        assert await _read(api) == []
        await api.aclose()

    run(scenario())
    assert len(mailcow["requests"]) == 3


def test_requests_during_the_probe_are_refused(mailcow, clock):
    mailcow["answer"] = _raise(httpx.ConnectError)
    api = _api()

    async def scenario():
        with pytest.raises(MailcowAPIError):
            await _read(api)
        clock["t"] += 31
        started, release = asyncio.Event(), asyncio.Event()

        async def slow(request):
            started.set()
            await release.wait()
            return httpx.Response(200, json=["probe"])
        mailcow["answer"] = slow
        probe = asyncio.create_task(_read(api))
        await started.wait()
        for _ in range(3):
            with pytest.raises(MailcowUnreachableError):
                await _read(api)
        release.set()
        assert await probe == ["probe"]
        await api.aclose()

    run(scenario())
    assert len(mailcow["requests"]) == 2


def test_event_loops_in_other_threads_share_what_is_known(mailcow):
    """Manual job runs use worker threads with their own event loops."""
    mailcow["answer"] = _raise(httpx.ConnectError)
    api = _api()
    outcomes = []

    def in_thread():
        async def read():
            try:
                await _read(api)
            except MailcowAPIError as e:
                outcomes.append(type(e))
        asyncio.run(read())

    for _ in range(2):
        worker = threading.Thread(target=in_thread)
        worker.start()
        worker.join(10)
    assert outcomes == [MailcowAPIError, MailcowUnreachableError]
    assert len(mailcow["requests"]) == 1


# ---------- a Settings save ----------

def test_a_new_address_is_tried_at_once_and_a_late_outcome_of_the_old_one_is_ignored(mailcow, clock, monkeypatch):
    mailcow["answer"] = _raise(httpx.ConnectError)
    api = _api()

    async def scenario():
        with pytest.raises(MailcowAPIError):
            await _read(api)
        clock["t"] += 31
        started, release = asyncio.Event(), asyncio.Event()

        async def fails_late(request):
            started.set()
            await release.wait()
            raise httpx.ConnectError("refused", request=request)
        mailcow["answer"] = fails_late
        probe = asyncio.create_task(_read(api))
        await started.wait()
        # Saved in Settings while the probe runs: the same host, written differently
        monkeypatch.setattr(settings._inner, "mailcow_url", URL + ":443")
        api.reload_config()
        release.set()
        with pytest.raises(MailcowAPIError):
            await probe
        mailcow["answer"] = lambda request: httpx.Response(200, json=[])
        assert await _read(api) == [], "the old request's failure must not refuse the new address"
        await api.aclose()

    run(scenario())
    assert len(mailcow["requests"]) == 3


def test_a_changed_timeout_tries_at_once(mailcow, monkeypatch):
    mailcow["answer"] = _raise(httpx.ConnectError)
    api = _api()

    async def scenario():
        with pytest.raises(MailcowAPIError):
            await _read(api)
        monkeypatch.setattr(settings._inner, "mailcow_api_timeout", api.timeout + 5)
        api.reload_config()
        mailcow["answer"] = lambda request: httpx.Response(200, json=[])
        assert await _read(api) == []
        await api.aclose()

    run(scenario())


def test_an_unrelated_settings_save_keeps_mailcow_refused(mailcow, monkeypatch):
    mailcow["answer"] = _raise(httpx.ConnectError)
    api = _api()

    async def scenario():
        with pytest.raises(MailcowAPIError):
            await _read(api)
        monkeypatch.setattr(settings._inner, "mailcow_api_key", "another-key")
        api.reload_config()
        with pytest.raises(MailcowUnreachableError):
            await _read(api)
        await api.aclose()

    run(scenario())
    assert len(mailcow["requests"]) == 1


# ---------- Rspamd at its own address ----------

@pytest.fixture()
def rspamd_direct(monkeypatch):
    monkeypatch.setattr(settings._inner, "rspamd_password", "rspamd-pw")
    monkeypatch.setattr(settings._inner, "rspamd_url", "http://rspamd.example.test:11334")


def _by_host(down_host):
    def answer(request):
        if request.url.host == down_host:
            raise httpx.ConnectError("refused", request=request)
        return httpx.Response(200, json=[])
    return answer


def test_an_unreachable_rspamd_does_not_refuse_mailcow(mailcow, rspamd_direct):
    mailcow["answer"] = _by_host("rspamd.example.test")
    api = _api()

    async def scenario():
        with pytest.raises(MailcowAPIError):
            await api._make_rspamd_request("/rspamd/maps")
        with pytest.raises(MailcowUnreachableError):
            await api._make_rspamd_request("/rspamd/maps")
        assert (await api.check_rspamd_password())["error"] == "connection"
        assert await _read(api) == []
        await api.aclose()

    run(scenario())
    assert [r.url.host for r in mailcow["requests"]] == ["rspamd.example.test", "mail.example.com"]


def test_an_unreachable_mailcow_does_not_refuse_rspamd(mailcow, rspamd_direct):
    mailcow["answer"] = _by_host("mail.example.com")
    api = _api()

    async def scenario():
        with pytest.raises(MailcowAPIError):
            await _read(api)
        with pytest.raises(MailcowUnreachableError):
            await _read(api)
        response = await api._make_rspamd_request("/rspamd/maps")
        assert response.status_code == 200
        await api.aclose()

    run(scenario())
    assert [r.url.host for r in mailcow["requests"]] == ["mail.example.com", "rspamd.example.test"]


# ---------- the other requests ----------

def _mark_unreachable(api):
    async def go():
        with pytest.raises(MailcowAPIError):
            await _read(api)
    return go()


def test_every_kind_of_request_is_refused_locally(mailcow, monkeypatch):
    monkeypatch.setattr(settings._inner, "rspamd_password", "rspamd-pw")
    monkeypatch.setattr(settings._inner, "rspamd_url", "")
    mailcow["answer"] = _raise(httpx.ConnectError)
    api = _api()
    api.headers_rw = {"X-API-Key": "rw", "Content-Type": "application/json"}

    async def scenario():
        await _mark_unreachable(api)
        assert await api.test_connection() is False
        with pytest.raises(MailcowUnreachableError):
            await api.get_quarantine_details("1")
        with pytest.raises(MailcowUnreachableError):
            await api._make_rspamd_request("/rspamd/maps")
        with pytest.raises(MailcowUnreachableError):
            await api.release_quarantine(["1"])
        # The credential checks keep their answer
        assert await api.check_rw_key() == {"configured": True, "valid": False, "error": "connection"}
        assert await api.check_rspamd_password() == {"configured": True, "valid": False, "error": "connection"}
        await api.aclose()

    run(scenario())
    assert len(mailcow["requests"]) == 1


def test_a_write_whose_connection_failed_is_sent_once_and_fails_at_once(mailcow):
    """No wait patched out: the page is told within the second."""
    mailcow["answer"] = _raise(httpx.ConnectError)
    api = _api()
    api.headers_rw = {"X-API-Key": "rw", "Content-Type": "application/json"}
    start = time.monotonic()
    with pytest.raises(MailcowAPIError) as raised:
        run(_closing(api, api.release_quarantine(["1"])))
    assert time.monotonic() - start < 1
    assert not isinstance(raised.value, MailcowWriteUnknownError)
    assert len(mailcow["requests"]) == 1


# ---------- which failures can pass ----------

@pytest.mark.parametrize("answer, transient", [
    (_raise(httpx.ConnectError), True),
    (_raise(httpx.ReadTimeout), True),
    (lambda request: httpx.Response(502), True),
    (lambda request: httpx.Response(401), False),
    (lambda request: httpx.Response(403), False),
    (lambda request: httpx.Response(404), False),
    (lambda request: httpx.Response(200, content=b"<html>", headers={"content-type": "application/json"}), False),
], ids=["connect", "read-timeout", "502", "401", "403", "404", "not-json"])
def test_a_failure_says_whether_it_can_pass(mailcow, answer, transient):
    mailcow["answer"] = answer
    api = _api()
    with pytest.raises(MailcowAPIError) as raised:
        run(_closing(api, _read(api)))
    assert raised.value.transient is transient


def test_a_refused_write_key_cannot_pass():
    assert mod.MailcowRwKeyError("rejected").transient is False
    assert MailcowAPIError("anything").transient is False


# ---------- startup ----------

def test_startup_does_not_ask_mailcow(mailcow, monkeypatch):
    # app.main mounts the frontend folder of the image, which a test run does not have
    import starlette.staticfiles as sf
    real_init = sf.StaticFiles.__init__
    monkeypatch.setattr(sf.StaticFiles, "__init__", lambda s, *a, **k: real_init(s, *a, **{**k, "check_dir": False}))
    from app import main, migrations
    mailcow["answer"] = _raise(httpx.ConnectError)
    monkeypatch.setattr(settings._inner, "edit_settings_via_ui_enabled", False)
    monkeypatch.setattr(main, "init_db", lambda: None)
    monkeypatch.setattr(main, "check_db_connection", lambda: True)
    monkeypatch.setattr(main, "run_migrations", lambda: None)
    monkeypatch.setattr(migrations, "run_alembic_upgrade", lambda: None)
    monkeypatch.setattr(main, "is_license_configured", lambda: False)
    monkeypatch.setattr(main, "start_scheduler", lambda: None)
    monkeypatch.setattr(main, "stop_scheduler", lambda: None)
    monkeypatch.setattr(main, "start_raw_logs_scheduler", lambda: None)
    monkeypatch.setattr(main, "stop_raw_logs_scheduler", lambda: None)
    monkeypatch.setattr(main, "log_agent_access_state", lambda: None)

    @asynccontextmanager
    async def no_maintenance():
        yield
    monkeypatch.setattr(main, "auth_store_maintenance", no_maintenance)
    monkeypatch.setattr(domains, "_server_ip_cache", None)

    async def start():
        async with main.lifespan(main.app):
            pass
    run(start())
    assert mailcow["requests"] == []


# ---------- the server IP for the transport sync ----------

@pytest.fixture()
def transports(monkeypatch):
    monkeypatch.setattr(type(settings._inner), "is_feature_enabled", lambda self, name: True)
    monkeypatch.setattr(settings._inner, "mailcow_api_key", "test-key")
    monkeypatch.setattr(settings._inner, "blacklist_source_transports", False)
    monkeypatch.setattr(settings._inner, "blacklist_source_relayhosts", False)
    monkeypatch.setattr(settings._inner, "blacklist_source_server_ip", True)
    monkeypatch.setattr(settings._inner, "blacklist_source_manual_hosts", "")
    monkeypatch.setattr(domains, "_server_ip_cache", None)
    store = Mock(return_value=(0, 0, 0))
    monkeypatch.setattr(scheduler, "_store_monitored_hosts", store)
    monkeypatch.setattr(scheduler, "check_monitored_hosts_job", AsyncMock())
    monkeypatch.setattr(scheduler, "update_job_status", Mock())
    return store


def _host_ip_answer(monkeypatch, answer):
    async def request(endpoint, *args, **kwargs):
        assert endpoint == "/api/v1/get/status/host/ip"
        if isinstance(answer, Exception):
            raise answer
        return answer
    monkeypatch.setattr(scheduler.mailcow_api, "_make_request", request)


@pytest.mark.parametrize("error", [MailcowUnreachableError(), MailcowAPIError("API returned status 502", transient=True)],
                         ids=["unreachable", "502"])
def test_the_transport_sync_fails_without_touching_hosts_when_the_ip_cannot_be_asked(transports, monkeypatch, error):
    _host_ip_answer(monkeypatch, error)
    run(scheduler.sync_transports_job())
    transports.assert_not_called()
    scheduler.update_job_status.assert_called_with("sync_transports", "failed", str(error))
    assert domains.get_cached_server_ip() is None


def test_the_transport_sync_goes_on_when_mailcow_answered_without_an_ip(transports, monkeypatch):
    _host_ip_answer(monkeypatch, {})
    run(scheduler.sync_transports_job())
    transports.assert_called_once_with({})
    scheduler.update_job_status.assert_called_with("sync_transports", "success")


def test_the_transport_sync_reads_the_ip_it_needs(transports, monkeypatch):
    _host_ip_answer(monkeypatch, [{"ipv4": "203.0.113.25"}])
    run(scheduler.sync_transports_job())
    transports.assert_called_once_with({"203.0.113.25": "system"})
    assert domains.get_cached_server_ip() == "203.0.113.25"


# ---------- the Rspamd import waits for the domain list ----------

@pytest.fixture()
def domain_cache(monkeypatch):
    """The domain list as at startup: never read."""
    monkeypatch.setattr(config, "_cached_active_domains", None)
    monkeypatch.setattr(config, "_cached_domains_complete", None)
    monkeypatch.setattr(config, "_cached_hosted_domains", set())
    monkeypatch.setattr(scheduler, "_persist_local_domain_aliases", lambda alias_map: None)
    monkeypatch.setattr("app.services.alias_domains.set_cached_alias_domain_map", lambda alias_map: None)
    monkeypatch.setattr(scheduler, "update_job_status", Mock())
    monkeypatch.setitem(scheduler._resume_offset, "rspamd", 500)
    discover = AsyncMock(return_value=0)
    monkeypatch.setattr(scheduler, "_discover_total_logs", discover)
    return discover


def test_the_rspamd_import_waits_for_the_domains_while_postfix_and_netfilter_import(domain_cache, monkeypatch):
    monkeypatch.setattr(type(settings._inner), "is_feature_enabled", lambda self, name: True)
    monkeypatch.setattr(scheduler, "_run_protection_rules_locked", AsyncMock())

    async def scenario():
        held, release = asyncio.Event(), asyncio.Event()
        imported = {"postfix": asyncio.Event(), "netfilter": asyncio.Event()}

        async def domain_sync():
            held.set()
            await release.wait()
            return False   # mailcow could not be asked
        monkeypatch.setattr(scheduler, "sync_local_domains", domain_sync)
        monkeypatch.setattr(scheduler, "fetch_and_store_postfix", AsyncMock(side_effect=lambda: imported["postfix"].set()))
        monkeypatch.setattr(scheduler, "fetch_and_store_netfilter", AsyncMock(side_effect=lambda: imported["netfilter"].set()))
        fetch = asyncio.create_task(scheduler.fetch_all_logs())
        await asyncio.wait_for(held.wait(), 5)
        # The domain sync is still held: Postfix and Netfilter do not wait for it
        await asyncio.wait_for(asyncio.gather(*(e.wait() for e in imported.values())), 5)
        release.set()
        await fetch

    run(scenario())
    domain_cache.assert_not_awaited()
    assert scheduler._resume_offset["rspamd"] == 500, "the next run resumes where the last one stopped"
    scheduler.update_job_status.assert_called_with("fetch_logs", "success")


def _domain_answers(monkeypatch, primary, alias):
    async def request(endpoint, *args, **kwargs):
        return {"/api/v1/get/domain/all": primary, "/api/v1/get/alias-domain/all": alias}[endpoint]
    monkeypatch.setattr(scheduler.mailcow_api, "_make_request", request)


def test_a_mailcow_without_domains_lets_the_rspamd_import_run(domain_cache, monkeypatch):
    """mailcow answers {} for both lists when it has no domains."""
    _domain_answers(monkeypatch, {}, {})
    run(scheduler.fetch_and_store_rspamd())
    assert config.local_domains_complete(scheduler.mailcow_api.base_url)
    domain_cache.assert_awaited_once_with("rspamd-history")
    # Still a failed sync on the Status page, as before
    scheduler.update_job_status.assert_any_call("sync_local_domains", "failed", "No domains")


def test_an_empty_answer_keeps_the_domains_this_mailcow_gave_before(domain_cache, monkeypatch):
    """mailcow may answer {} for a moment while it starts: the list it gave
    before stays, or every direction would be stored wrong until the next sync."""
    url = scheduler.mailcow_api.base_url
    config.set_cached_active_domains(["example.com"], complete_for=url)
    _domain_answers(monkeypatch, {}, {})
    run(scheduler.sync_local_domains())
    assert config.get_cached_active_domains() == ["example.com"]
    assert config.local_domains_complete(url)
    scheduler.update_job_status.assert_any_call("sync_local_domains", "failed", "No domains")


def test_an_empty_answer_replaces_a_list_of_another_mailcow(domain_cache, monkeypatch):
    config.set_cached_active_domains(["example.org"], complete_for="https://old.example.net")
    _domain_answers(monkeypatch, {}, {})
    run(scheduler.sync_local_domains())
    assert config.get_cached_active_domains() == []
    assert config.local_domains_complete(scheduler.mailcow_api.base_url)


def test_domains_read_once_are_not_read_again(domain_cache, monkeypatch):
    _domain_answers(monkeypatch, [{"domain_name": "example.com", "active": 1}], {})
    run(scheduler.fetch_and_store_rspamd())
    assert config.local_domains_complete(scheduler.mailcow_api.base_url)
    sync = AsyncMock()
    monkeypatch.setattr(scheduler, "sync_local_domains", sync)
    run(scheduler.fetch_and_store_rspamd())
    sync.assert_not_awaited()
    assert domain_cache.await_count == 2


@pytest.mark.parametrize("primary, alias", [
    (None, {}),
    ({"type": "error", "msg": "access denied"}, {}),
    ("domains", {}),
    (5, {}),
    ([{"domain_name": "example.com", "active": 1}], None),
    ([{"domain_name": "example.com", "active": 1}], {"type": "error", "msg": "access denied"}),
    ([{"domain_name": "example.com", "active": 1}], "aliases"),
], ids=["null", "error-object", "string", "number", "alias-null", "alias-error-object", "alias-string"])
def test_an_answer_that_is_not_a_domain_list_keeps_the_rspamd_import_waiting(domain_cache, monkeypatch, primary, alias):
    config.set_cached_active_domains(["example.org"])   # an earlier list, of no known mailcow
    _domain_answers(monkeypatch, primary, alias)
    run(scheduler.fetch_and_store_rspamd())
    assert not config.local_domains_complete(scheduler.mailcow_api.base_url)
    domain_cache.assert_not_awaited()
    assert scheduler._resume_offset["rspamd"] == 500
    assert config.get_cached_active_domains() == ["example.org"], "a failed sync keeps the previous list"


@pytest.mark.parametrize("answer", [None, {"type": "error"}, "domains", 5], ids=["null", "error-object", "string", "number"])
def test_a_strict_domain_read_refuses_what_is_not_a_list(monkeypatch, answer):
    monkeypatch.setattr(mod.mailcow_api, "_make_request", AsyncMock(return_value=answer))
    with pytest.raises(MailcowAPIError) as raised:
        run(mod.mailcow_api.get_domains(strict=True))
    assert raised.value.transient is False
    # Other readers keep reading it as none
    assert run(mod.mailcow_api.get_domains()) == []


def test_a_strict_domain_read_takes_mailcows_empty_answer(monkeypatch):
    monkeypatch.setattr(mod.mailcow_api, "_make_request", AsyncMock(return_value={}))
    assert run(mod.mailcow_api.get_domains(strict=True)) == []
    assert run(mod.mailcow_api.get_alias_domain_map(strict=True)) == {}


@pytest.mark.parametrize("answer", [None, "aliases", 5], ids=["null", "string", "number"])
def test_a_strict_alias_read_refuses_what_is_not_a_list(monkeypatch, answer):
    monkeypatch.setattr(mod.mailcow_api, "_make_request", AsyncMock(return_value=answer))
    with pytest.raises(MailcowAPIError) as raised:
        run(mod.mailcow_api.get_alias_domain_map(strict=True))
    assert raised.value.transient is False
    assert run(mod.mailcow_api.get_alias_domain_map()) == {}
