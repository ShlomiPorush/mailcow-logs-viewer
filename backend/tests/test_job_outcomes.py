import asyncio
import smtplib
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from app import scheduler
from app.config import settings
from app.main import app
from app.mailcow_api import MailcowAPIError
from app.routers import reporting
from app.services import smtp_service
from app.services.job_status import job_status


async def _nothing(*args, **kwargs):
    return None


@pytest.fixture()
def imports(monkeypatch):
    monkeypatch.setattr(settings._inner, 'disabled_features', '')
    monkeypatch.setattr(scheduler, '_run_protection_rules_locked', _nothing)
    for name in ('postfix', 'rspamd', 'netfilter'):
        monkeypatch.setattr(scheduler, f'fetch_and_store_{name}', _nothing)
    scheduler._log_count_cache.clear()
    yield
    scheduler._log_count_cache.clear()


def test_a_run_in_which_an_import_failed_is_failed_and_names_it(imports, monkeypatch):
    monkeypatch.setattr(scheduler, 'fetch_and_store_rspamd', AsyncMock(side_effect=MailcowAPIError('no answer')))
    asyncio.run(scheduler.fetch_all_logs())
    assert job_status['fetch_logs']['status'] == 'failed'
    assert 'Rspamd: no answer' in job_status['fetch_logs']['error']
    assert 'Postfix' not in job_status['fetch_logs']['error']


def test_a_run_in_which_every_import_worked_is_a_success(imports):
    asyncio.run(scheduler.fetch_all_logs())
    assert job_status['fetch_logs']['status'] == 'success'


def test_security_turned_off_during_a_failed_import_still_names_the_import(imports, monkeypatch):
    async def off_and_fail():
        settings._inner.__dict__['disabled_features'] = 'netfilter'
        raise MailcowAPIError('no answer')
    monkeypatch.setattr(scheduler, 'fetch_and_store_netfilter', off_and_fail)
    asyncio.run(scheduler.fetch_all_logs())
    assert 'Netfilter: no answer' in job_status['fetch_logs']['error']


@pytest.mark.parametrize('name', ['postfix', 'rspamd', 'netfilter'])
def test_an_importer_reports_that_mailcow_did_not_answer(monkeypatch, name):
    scheduler._log_count_cache.clear()
    scheduler._resume_offset.update(postfix=0, rspamd=0)
    monkeypatch.setattr(scheduler, 'local_domains_complete', lambda url: True)
    monkeypatch.setattr(scheduler.mailcow_api, '_make_request', AsyncMock(side_effect=MailcowAPIError('no answer')))
    with pytest.raises(MailcowAPIError):
        asyncio.run(getattr(scheduler, f'fetch_and_store_{name}')())
    assert scheduler._log_count_cache == {}


def test_an_empty_mailcow_is_no_failure(monkeypatch):
    scheduler._log_count_cache.clear()
    scheduler._resume_offset.update(postfix=0, rspamd=0)
    monkeypatch.setattr(scheduler, 'local_domains_complete', lambda url: True)
    monkeypatch.setattr(scheduler.mailcow_api, '_make_request', AsyncMock(return_value={}))
    asyncio.run(scheduler.fetch_and_store_postfix())
    asyncio.run(scheduler.fetch_and_store_rspamd())
    scheduler._log_count_cache.clear()


def test_a_cancelled_queue_cleanup_is_not_a_success(monkeypatch):
    monkeypatch.setattr(scheduler, 'handling_on', lambda: True)
    monkeypatch.setattr(settings._inner, 'queue_cleanup_enabled', True)
    monkeypatch.setattr(type(scheduler.mailcow_api), 'has_rw_key', property(lambda self: True))
    monkeypatch.setattr(scheduler, '_local_domains_known', AsyncMock(return_value='source'))
    monkeypatch.setattr(scheduler, 'cleanup_blocks', lambda: False)
    monkeypatch.setattr(scheduler.mailcow_api, 'get_queue', AsyncMock(side_effect=asyncio.CancelledError))
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(scheduler.cleanup_deferred_queue_job())
    assert job_status['cleanup_deferred_queue']['status'] != 'success'


def _run_by_hand(monkeypatch, job):
    monkeypatch.setattr(settings._inner, 'auth_enabled', False)
    monkeypatch.setattr(settings._inner, 'basic_auth_enabled', False)
    monkeypatch.setattr(settings._inner, 'oauth2_enabled', False)
    monkeypatch.setattr(scheduler, 'expire_old_correlations', job)
    job_status['expire_correlations'] = {'last_run': None, 'status': 'idle', 'error': None}
    answer = TestClient(app).post('/api/settings/jobs/expire_correlations/run')
    assert answer.status_code == 200
    return job_status['expire_correlations']


def test_a_job_run_by_hand_keeps_the_failure_it_reported(monkeypatch):
    async def job():
        scheduler.update_job_status('expire_correlations', 'running')
        scheduler.update_job_status('expire_correlations', 'failed', 'the database is down')
    entry = _run_by_hand(monkeypatch, job)
    assert entry['status'] == 'failed' and entry['error'] == 'the database is down'


def test_a_job_run_by_hand_that_reports_nothing_is_a_success(monkeypatch):
    assert _run_by_hand(monkeypatch, _nothing)['status'] == 'success'


@pytest.fixture()
def summary(monkeypatch):
    monkeypatch.setattr(settings._inner, 'enable_weekly_summary', True)
    monkeypatch.setattr(settings._inner, 'admin_email', 'admin@example.com')
    monkeypatch.setattr(type(settings._inner), 'notification_smtp_configured', property(lambda self: True))
    monkeypatch.setattr(reporting, 'get_system_summary_data', AsyncMock(return_value={}))
    monkeypatch.setattr(reporting, 'build_summary_email', lambda data: ('subject', 'text', 'html'))


def _summary_job(monkeypatch, sent=True):
    sends = []
    monkeypatch.setattr(reporting, 'send_notification_email', lambda *args: sends.append(args) or sent)
    asyncio.run(scheduler.send_weekly_summary_email_job())
    return sends


def test_a_weekly_summary_that_was_sent_is_a_success(summary, monkeypatch):
    assert len(_summary_job(monkeypatch)) == 1
    assert job_status['send_weekly_summary']['status'] == 'success'


def test_a_weekly_summary_that_was_not_sent_is_failed(summary, monkeypatch):
    _summary_job(monkeypatch, sent=False)
    assert job_status['send_weekly_summary']['status'] == 'failed'


def test_a_weekly_summary_without_data_is_failed_and_not_sent(summary, monkeypatch):
    monkeypatch.setattr(reporting, 'get_system_summary_data', AsyncMock(side_effect=RuntimeError('no data')))
    assert _summary_job(monkeypatch) == []
    assert job_status['send_weekly_summary'] == {**job_status['send_weekly_summary'], 'status': 'failed', 'error': 'no data'}


def test_a_weekly_summary_with_nowhere_to_go_says_what_is_missing(summary, monkeypatch):
    monkeypatch.setattr(settings._inner, 'admin_email', '')
    assert _summary_job(monkeypatch) == []
    assert job_status['send_weekly_summary']['status'] == 'idle'
    assert 'admin email' in job_status['send_weekly_summary']['error']


@pytest.mark.parametrize('broken', ['get_mailbox_stats_summary', 'get_all_mailbox_stats'])
def test_the_summary_is_not_built_from_the_zeros_of_a_failed_read(monkeypatch, broken):
    answers = {'get_mailbox_stats_summary': {'total_sent': 5}, 'get_all_mailbox_stats': {'mailboxes': []}}
    answers[broken] = {'error': 'Unable to load mailbox statistics.', 'mailboxes': []}
    for name, answer in answers.items():
        monkeypatch.setattr(reporting, name, lambda answer=answer, **kwargs: answer)
    with pytest.raises(RuntimeError, match='Unable to load'):
        reporting._get_summary_statistics_worker()


class FakeSmtp:
    made = []
    quit_error = None
    send_error = None
    refused = {}

    def __init__(self, host, port, timeout=None, **kwargs):
        self.timeout, self.closed = timeout, False
        FakeSmtp.made.append(self)

    def login(self, *args):
        pass

    def sendmail(self, *args):
        if FakeSmtp.send_error:
            raise FakeSmtp.send_error
        return FakeSmtp.refused

    def quit(self):
        if FakeSmtp.quit_error:
            raise FakeSmtp.quit_error

    def close(self):
        self.closed = True


@pytest.fixture()
def smtp(monkeypatch):
    for name, value in (('made', []), ('quit_error', None), ('send_error', None), ('refused', {})):
        monkeypatch.setattr(FakeSmtp, name, value)
    monkeypatch.setattr(smtp_service.smtplib, 'SMTP', FakeSmtp)
    monkeypatch.setattr(smtp_service.smtplib, 'SMTP_SSL', FakeSmtp)
    monkeypatch.setattr(type(settings._inner), 'notification_smtp_configured', property(lambda self: True))
    for key, value in {'smtp_relay_mode': True, 'smtp_use_ssl': False, 'smtp_use_tls': False, 'smtp_port': 25,
                       'smtp_host': 'smtp.example.com', 'smtp_from': 'logs@example.com'}.items():
        monkeypatch.setattr(settings._inner, key, value)
    return FakeSmtp


def _send():
    return smtp_service.send_notification_email('admin@example.com', 'subject', 'text')


@pytest.mark.parametrize('port', [25, 465])
def test_sending_has_a_timeout_and_closes_its_connection(smtp, monkeypatch, port):
    monkeypatch.setattr(settings._inner, 'smtp_port', port)
    assert _send() is True
    assert smtp.made[0].timeout and smtp.made[0].closed


def test_a_failed_send_closes_its_connection(smtp, monkeypatch):
    monkeypatch.setattr(smtp, 'send_error', smtplib.SMTPDataError(554, b'refused'))
    assert _send() is False
    assert smtp.made[0].closed


@pytest.mark.parametrize('error', [smtplib.SMTPServerDisconnected('gone'), TimeoutError()])
def test_an_accepted_email_is_sent_whatever_the_goodbye(smtp, monkeypatch, error):
    monkeypatch.setattr(smtp, 'quit_error', error)
    assert _send() is True
    assert smtp.made[0].closed
