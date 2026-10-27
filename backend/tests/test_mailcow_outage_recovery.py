"""After mailcow comes back, the app recovers by itself.

The domain sync, the transport sync, the DNS check and the credential checks
run every few hours. One that failed because mailcow could not answer stayed
failed until its next run, up to six hours later, and an unknown server IP
until a restart. retry_failed_jobs runs them again every five minutes while
their last failure was transient, and never after a refusal: a rejected key is
a failed login for mailcow's Fail2ban. A manual Run of a failing job was marked
a success; it keeps its failure now.
"""
import asyncio
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, Mock

import httpx
import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from fastapi import HTTPException  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from starlette.background import BackgroundTasks  # noqa: E402

from app import database, scheduler  # noqa: E402
from app.config import settings  # noqa: E402
from app.mailcow_api import MailcowAPIError, MailcowUnreachableError  # noqa: E402
from app.routers import domains  # noqa: E402
from app.routers import settings as settings_router  # noqa: E402

# status key -> the scheduler job that runs it every few hours
TARGETS = {'sync_local_domains': 'sync_local_domains', 'sync_transports': 'sync_transports',
           'dns_check': 'dns_check_background', 'check_credentials': 'check_credentials'}
UNREACHABLE = "mailcow cannot be reached. It is tried again within 30 seconds."


def run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _restore_job_status():
    saved = {k: dict(v) for k, v in scheduler.job_status.items()}
    yield
    scheduler.job_status.clear()
    scheduler.job_status.update(saved)


@pytest.fixture
def features(monkeypatch):
    """Every feature on; add a name to turn it off."""
    off = set()
    monkeypatch.setattr(type(settings._inner), "is_feature_enabled", lambda self, name: name not in off)
    return off


@pytest.fixture
def jobs(monkeypatch, features):
    """The scheduler with every periodic target registered, and the server IP known."""
    fake = Mock()
    fake.registered = set(TARGETS.values())
    fake.get_job.side_effect = lambda job_id: Mock(id=job_id) if job_id in fake.registered else None
    monkeypatch.setattr(scheduler, "scheduler", fake)
    monkeypatch.setattr(domains, "_server_ip_cache", "203.0.113.25")
    fake.init_server_ip = AsyncMock(return_value="203.0.113.25")
    monkeypatch.setattr(scheduler, "init_server_ip", fake.init_server_ip)
    return fake


def _failed(key, retryable=True, error=UNREACHABLE):
    scheduler.update_job_status(key, 'failed', error, retryable=retryable)


def _retried(fake):
    return sorted(c.args[0] for c in fake.modify_job.call_args_list)


# ---------- which jobs run again ----------

def test_a_job_that_failed_on_a_transient_error_runs_again_now(jobs):
    for key in TARGETS:
        _failed(key)
    before = datetime.now(timezone.utc)
    run(scheduler.retry_failed_jobs())
    assert _retried(jobs) == sorted(TARGETS.values())
    for call in jobs.modify_job.call_args_list:
        assert before <= call.kwargs['next_run_time'] <= datetime.now(timezone.utc)
    jobs.add_job.assert_not_called()


@pytest.mark.parametrize("status, retryable", [('failed', False), ('success', True), ('running', True), ('idle', True)],
                         ids=["failed-for-good", "success", "running", "idle"])
def test_only_a_transient_failure_runs_again(jobs, status, retryable):
    for key in TARGETS:
        scheduler.job_status[key] = {'last_run': None, 'status': status, 'error': None, 'retryable': retryable}
    run(scheduler.retry_failed_jobs())
    jobs.modify_job.assert_not_called()
    jobs.add_job.assert_not_called()


def test_a_job_that_never_ran_does_not_run_again(jobs):
    scheduler.job_status.pop('sync_local_domains', None)
    run(scheduler.retry_failed_jobs())
    jobs.modify_job.assert_not_called()


@pytest.mark.parametrize("key, feature", [('sync_transports', 'blacklist'), ('dns_check', 'domains')])
def test_a_job_of_a_feature_turned_off_does_not_run_again(jobs, features, key, feature):
    _failed(key)
    features.add(feature)
    run(scheduler.retry_failed_jobs())
    jobs.modify_job.assert_not_called()
    # Read at each run, not at startup: turned on again, it runs
    features.discard(feature)
    run(scheduler.retry_failed_jobs())
    assert _retried(jobs) == [TARGETS[key]]


def test_a_job_not_registered_gets_a_one_off_run_and_the_others_still_run(jobs):
    jobs.registered.discard('sync_transports')   # Blacklist turned on after startup
    for key in TARGETS:
        _failed(key)
    run(scheduler.retry_failed_jobs())
    assert _retried(jobs) == sorted(v for k, v in TARGETS.items() if k != 'sync_transports')
    jobs.add_job.assert_called_once()
    call = jobs.add_job.call_args
    assert call.args[0] is scheduler.sync_transports_job and call.args[1] == 'date'
    assert call.kwargs['id'] == 'sync_transports_retry' and call.kwargs['replace_existing'] is True


def test_one_target_that_breaks_does_not_stop_the_others(jobs):
    for key in TARGETS:
        _failed(key)

    def modify(job_id, **kwargs):
        if job_id == 'sync_local_domains':
            raise RuntimeError("job store gone")

    def get_job(job_id):
        if job_id == 'sync_transports':
            raise RuntimeError("lookup failed")
        return Mock(id=job_id)

    jobs.modify_job.side_effect = modify
    jobs.get_job.side_effect = get_job
    run(scheduler.retry_failed_jobs())
    # The two after them still ran
    assert _retried(jobs) == ['check_credentials', 'dns_check_background', 'sync_local_domains']


# ---------- the server IP ----------

def test_an_unknown_server_ip_is_read_again(jobs, monkeypatch):
    monkeypatch.setattr(domains, "_server_ip_cache", None)
    run(scheduler.retry_failed_jobs())
    jobs.init_server_ip.assert_awaited_once()


def test_a_known_server_ip_is_not_read_again(jobs):
    run(scheduler.retry_failed_jobs())
    jobs.init_server_ip.assert_not_awaited()


def test_the_server_ip_failing_does_not_stop_the_jobs(jobs, monkeypatch):
    monkeypatch.setattr(domains, "_server_ip_cache", None)
    jobs.init_server_ip.side_effect = RuntimeError("boom")
    _failed('check_credentials')
    run(scheduler.retry_failed_jobs())
    assert _retried(jobs) == ['check_credentials']


# ---------- registration ----------

def test_the_retry_runs_every_five_minutes_and_is_not_a_job_on_status(monkeypatch):
    fake = Mock()
    monkeypatch.setattr(scheduler, "scheduler", fake)
    monkeypatch.setattr(scheduler, "cleanup_disabled_feature_data", lambda *a, **k: None)
    scheduler.start_scheduler()
    retry = [c for c in fake.add_job.call_args_list if c.kwargs.get('id') == 'retry_failed_jobs']
    assert len(retry) == 1
    assert retry[0].args[0] is scheduler.retry_failed_jobs
    assert retry[0].kwargs['max_instances'] == 1
    assert retry[0].kwargs['trigger'].interval == timedelta(minutes=5)
    # Not on Status, and no Run button for it
    assert 'retry_failed_jobs' not in scheduler.job_status
    with pytest.raises(HTTPException) as refused:
        settings_router.trigger_job('retry_failed_jobs', BackgroundTasks())
    assert refused.value.status_code == 404


# ---------- each job says whether its failure can pass ----------

TRANSIENT_ERRORS = [
    (MailcowUnreachableError(), True),
    (MailcowAPIError("API returned status 502", transient=True), True),
    (httpx.ConnectError("connection refused"), True),
    (MailcowAPIError("API returned status 403"), False),
    (MailcowAPIError("Unexpected domains answer: None"), False),
]
TRANSIENT_IDS = ["unreachable", "502", "httpx-connect", "403", "bad-answer"]


@pytest.mark.parametrize("error, retryable", TRANSIENT_ERRORS, ids=TRANSIENT_IDS)
def test_the_domain_sync_says_whether_its_failure_can_pass(monkeypatch, error, retryable):
    monkeypatch.setattr(scheduler.mailcow_api, "get_domains", AsyncMock(side_effect=error))
    monkeypatch.setattr(scheduler, "set_cached_active_domains", Mock())
    run(scheduler.sync_local_domains())
    state = scheduler.job_status['sync_local_domains']
    assert (state['status'], state['retryable']) == ('failed', retryable)


def test_a_mailcow_without_domains_is_not_run_again_early(monkeypatch):
    monkeypatch.setattr(scheduler.mailcow_api, "get_domains", AsyncMock(return_value=[]))
    monkeypatch.setattr(scheduler.mailcow_api, "get_alias_domain_map", AsyncMock(return_value={}))
    monkeypatch.setattr(scheduler, "set_cached_active_domains", Mock())
    run(scheduler.sync_local_domains())
    state = scheduler.job_status['sync_local_domains']
    assert (state['status'], state['error'], state['retryable']) == ('failed', 'No domains', False)


@pytest.fixture
def transports(monkeypatch, features):
    monkeypatch.setattr(settings._inner, "mailcow_api_key", "test-key")
    monkeypatch.setattr(settings._inner, "blacklist_source_transports", False)
    monkeypatch.setattr(settings._inner, "blacklist_source_relayhosts", False)
    monkeypatch.setattr(settings._inner, "blacklist_source_server_ip", True)
    monkeypatch.setattr(settings._inner, "blacklist_source_manual_hosts", "")
    store = Mock(return_value=(0, 0, 0))
    monkeypatch.setattr(scheduler, "_store_monitored_hosts", store)
    monkeypatch.setattr(scheduler, "check_monitored_hosts_job", AsyncMock())
    return store


@pytest.mark.parametrize("error, retryable", TRANSIENT_ERRORS, ids=TRANSIENT_IDS)
def test_the_transport_sync_says_whether_its_failure_can_pass(transports, monkeypatch, error, retryable):
    monkeypatch.setattr(domains, "load_server_ip", AsyncMock(side_effect=error))
    run(scheduler.sync_transports_job())
    transports.assert_not_called()
    state = scheduler.job_status['sync_transports']
    assert (state['status'], state['retryable']) == ('failed', retryable)


@pytest.mark.parametrize("error, retryable", TRANSIENT_ERRORS, ids=TRANSIENT_IDS)
def test_the_dns_check_says_whether_its_failure_can_pass(features, monkeypatch, error, retryable):
    monkeypatch.setattr(scheduler.mailcow_api, "get_domains", AsyncMock(side_effect=error))
    run(scheduler.check_all_domains_dns_background())
    state = scheduler.job_status['dns_check']
    assert (state['status'], state['retryable']) == ('failed', retryable)


def _credentials(monkeypatch, answers):
    """answers: name -> a list of check answers, one per run (None: not set);
    an exception in the list is raised by that run."""
    def check(name):
        async def answer():
            result = answers[name].pop(0)
            if isinstance(result, Exception):
                raise result
            return result
        return answer
    monkeypatch.setattr(settings_router, '_CREDENTIAL_CHECKS', {
        name: {'configured': (lambda n=name: answers[n] is not None), 'fingerprint': lambda n=name: f'fp-{n}',
               'check': check(name)}
        for name in ('mailcow_rw_key', 'rspamd_password')})
    monkeypatch.setattr(settings_router, '_persist_credential_status_worker', lambda *a: None)


def _refused(error, http_status=None):
    answer = {'configured': True, 'valid': False, 'error': error}
    if http_status is not None:
        answer['http_status'] = http_status
    return answer


ACCEPTED = {'configured': True, 'valid': True, 'error': None}


@pytest.mark.parametrize("rw, rspamd, retryable", [
    (_refused('connection'), None, True),
    (_refused('unexpected', 502), None, True),
    (None, _refused('unexpected', 503), True),
    (_refused('connection'), ACCEPTED, True),
    (_refused('unexpected', 404), None, False),
    (_refused('rejected', 401), None, False),
    (_refused('read_only', 403), None, False),
    (None, _refused('rejected', 401), False),
    (None, _refused('redirected', 302), False),
    (_refused('connection'), _refused('rejected', 401), False),
    (_refused('read_only', 403), _refused('connection'), False),
], ids=["connection", "502", "rspamd-503", "one-unreached", "404", "rejected", "read-only", "rspamd-rejected",
        "redirected", "unreached-and-rejected", "read-only-and-unreached"])
def test_the_credential_check_runs_again_only_when_the_server_could_not_answer(monkeypatch, rw, rspamd, retryable):
    _credentials(monkeypatch, {'mailcow_rw_key': rw and [rw], 'rspamd_password': rspamd and [rspamd]})
    run(scheduler.check_credentials_job())
    state = scheduler.job_status['check_credentials']
    assert (state['status'], state['retryable']) == ('failed', retryable)


def test_a_check_that_broke_off_is_never_retried_early(monkeypatch):
    """The Read-Write key check may have been answered with a refusal before it
    broke off (saving its result failed, say): retried every five minutes it
    would be one more failed login each time."""
    _credentials(monkeypatch, {'mailcow_rw_key': [RuntimeError("could not save the result")],
                               'rspamd_password': [_refused('connection')]})
    run(scheduler.check_credentials_job())
    state = scheduler.job_status['check_credentials']
    assert (state['status'], state['retryable']) == ('failed', False)


def test_credentials_unreached_then_502_then_accepted(jobs, monkeypatch):
    _credentials(monkeypatch, {'mailcow_rw_key': [_refused('connection'), _refused('unexpected', 502), ACCEPTED],
                               'rspamd_password': None})
    retried = []
    for _ in range(3):
        jobs.modify_job.reset_mock()
        run(scheduler.check_credentials_job())
        run(scheduler.retry_failed_jobs())
        retried.append(_retried(jobs))
    assert retried == [['check_credentials'], ['check_credentials'], []]
    assert scheduler.job_status['check_credentials']['status'] == 'success'


def test_a_rejected_key_is_not_checked_more_often(jobs, monkeypatch):
    _credentials(monkeypatch, {'mailcow_rw_key': [_refused('rejected', 401)], 'rspamd_password': None})
    run(scheduler.check_credentials_job())
    run(scheduler.retry_failed_jobs())
    jobs.modify_job.assert_not_called()
    jobs.add_job.assert_not_called()


# ---------- a manual Run keeps a failure ----------

def _manual_run(job):
    scheduler.job_status[job] = {'last_run': None, 'status': 'idle', 'error': None}
    tasks = BackgroundTasks()
    assert settings_router.trigger_job(job, tasks)['status'] == 'started'
    run(tasks())
    return scheduler.job_status[job]


def test_a_manual_transport_sync_that_fails_stays_failed(transports, monkeypatch):
    monkeypatch.setattr(domains, "load_server_ip", AsyncMock(side_effect=MailcowUnreachableError()))
    state = _manual_run('sync_transports')
    assert (state['status'], state['error']) == ('failed', UNREACHABLE)
    assert state.get('retryable') is True


def test_a_manual_domain_sync_that_fails_stays_failed(features, monkeypatch):
    monkeypatch.setattr(scheduler.mailcow_api, "get_domains", AsyncMock(side_effect=MailcowUnreachableError()))
    monkeypatch.setattr(scheduler, "set_cached_active_domains", Mock())
    state = _manual_run('sync_local_domains')
    assert (state['status'], state['error']) == ('failed', UNREACHABLE)
    assert state.get('retryable') is True


def test_a_manual_dns_check_that_fails_stays_failed(features, monkeypatch):
    monkeypatch.setattr(scheduler.mailcow_api, "get_domains", AsyncMock(side_effect=MailcowUnreachableError()))
    state = _manual_run('dns_check')
    assert (state['status'], state['error']) == ('failed', UNREACHABLE)
    assert state.get('retryable') is True


def test_a_manual_domain_sync_that_works_is_a_success(features, monkeypatch):
    monkeypatch.setattr(scheduler.mailcow_api, "get_domains", AsyncMock(return_value=[{"domain_name": "example.com", "active": 1}]))
    monkeypatch.setattr(scheduler.mailcow_api, "get_alias_domain_map", AsyncMock(return_value={}))
    monkeypatch.setattr(scheduler, "set_cached_active_domains", Mock())
    monkeypatch.setattr(scheduler, "_persist_local_domain_aliases", lambda alias_map: None)
    monkeypatch.setattr("app.services.alias_domains.set_cached_alias_domain_map", lambda alias_map: None)
    assert _manual_run('sync_local_domains')['status'] == 'success'


@pytest.mark.parametrize("error, retryable", TRANSIENT_ERRORS, ids=TRANSIENT_IDS)
def test_a_dns_check_without_the_alias_domains_says_whether_that_can_pass(features, monkeypatch, error, retryable):
    """The primary domains are checked; alias domains that could not be read
    for a passing reason leave the run failed, so it runs again soon."""
    monkeypatch.setattr(scheduler.mailcow_api, "get_domains", AsyncMock(return_value=[{"domain_name": "example.com", "active": 1}]))
    monkeypatch.setattr(scheduler.mailcow_api, "get_alias_domain_map", AsyncMock(side_effect=error))
    monkeypatch.setattr(domains, "get_spf_source_ips", AsyncMock(return_value=[]))
    checked = AsyncMock(return_value={})
    monkeypatch.setattr(scheduler, "check_domain_dns", checked)
    monkeypatch.setattr(scheduler, "store_dns_check_worker", lambda *a: None)
    assert run(scheduler.check_all_domains_dns_background()) == scheduler.JOB_STATUS_SET
    assert checked.await_args.args[0] == "example.com"
    state = scheduler.job_status["dns_check"]
    assert (state["status"], state["retryable"]) == (("failed", True) if retryable else ("success", False))


def test_a_dns_check_with_no_domains_does_not_stay_running(features, monkeypatch):
    """A status left on running refused every later manual Run with 409."""
    monkeypatch.setattr(scheduler.mailcow_api, "get_domains", AsyncMock(return_value=[]))
    assert run(scheduler.check_all_domains_dns_background()) == scheduler.JOB_STATUS_SET
    assert scheduler.job_status['dns_check']['status'] == 'success'


# ---------- the flag stays inside ----------

def _postgres_available() -> bool:
    try:
        with database.engine.connect():
            return True
    except Exception:
        return False


def test_the_settings_answer_does_not_show_whether_a_failure_can_pass(monkeypatch, features):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.main import app
    for key in ('auth_enabled', 'basic_auth_enabled', 'oauth2_enabled', 'edit_settings_via_ui_enabled'):
        if key in vars(settings):
            monkeypatch.delattr(settings, key)
        monkeypatch.setattr(settings._inner, key, False)
    database.init_db()
    for key in TARGETS:
        _failed(key)
    body = TestClient(app, raise_server_exceptions=False).get('/api/settings/info').json()
    jobs = body['background_jobs']
    assert jobs['sync_local_domains']['status'] == 'failed'
    assert jobs['sync_transports']['error'] == UNREACHABLE
    assert 'retryable' not in json.dumps(body)
