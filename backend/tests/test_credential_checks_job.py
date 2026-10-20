"""Credential Checks: the Read-Write API key and the Rspamd password are
checked by the app itself, soon after a start and every few hours, the same
way as Validate in Settings, and the result is kept for the page."""
import asyncio
from unittest.mock import Mock

import pytest

from app import scheduler
from app.routers import settings as rs


def _checks(monkeypatch, rw=None, rspamd=None):
    """rw / rspamd: the check's answer, or None when it is not set."""
    persisted = []
    monkeypatch.setattr(rs, '_CREDENTIAL_CHECKS', {
        'mailcow_rw_key': {'configured': lambda: rw is not None, 'fingerprint': lambda: 'fp-rw',
                           'check': lambda: _answer(rw)},
        'rspamd_password': {'configured': lambda: rspamd is not None, 'fingerprint': lambda: 'fp-rspamd',
                            'check': lambda: _answer(rspamd)},
    })
    monkeypatch.setattr(rs, '_persist_credential_status_worker',
                        lambda name, result, fingerprint: persisted.append((name, result['valid'], fingerprint)))
    status = Mock()
    monkeypatch.setattr(scheduler, 'update_job_status', status)
    return persisted, status


async def _answer(result):
    if isinstance(result, Exception):
        raise result
    return result


ACCEPTED = {'configured': True, 'valid': True, 'error': None}


def test_both_are_checked_and_kept_for_their_current_value(monkeypatch):
    persisted, status = _checks(monkeypatch, rw=ACCEPTED, rspamd=ACCEPTED)
    asyncio.run(scheduler.check_credentials_job())
    assert persisted == [('mailcow_rw_key', True, 'fp-rw'), ('rspamd_password', True, 'fp-rspamd')]
    status.assert_called_with('check_credentials', 'success')


def test_only_what_is_set_is_checked(monkeypatch):
    persisted, status = _checks(monkeypatch, rspamd=ACCEPTED)
    asyncio.run(scheduler.check_credentials_job())
    assert persisted == [('rspamd_password', True, 'fp-rspamd')]


def test_nothing_set_runs_nothing(monkeypatch):
    persisted, status = _checks(monkeypatch)
    asyncio.run(scheduler.check_credentials_job())
    assert persisted == [] and not status.called


@pytest.mark.parametrize('error, words', [('rejected', 'was rejected'), ('read_only', 'has no write access'),
                                          ('connection', 'could not be reached')])
def test_a_key_mailcow_does_not_accept_is_a_problem_on_status(monkeypatch, error, words):
    persisted, status = _checks(monkeypatch, rw={'configured': True, 'valid': False, 'error': error}, rspamd=ACCEPTED)
    asyncio.run(scheduler.check_credentials_job())
    assert ('mailcow_rw_key', False, 'fp-rw') in persisted, 'the result is kept, so the page shows it'
    job, state, message = status.call_args.args
    assert (job, state) == ('check_credentials', 'failed')
    assert message == f'The Read-Write API key {words}. See Settings > Mailcow.'


def test_a_check_that_breaks_does_not_stop_the_other(monkeypatch):
    persisted, status = _checks(monkeypatch, rw=RuntimeError('boom'), rspamd=ACCEPTED)
    asyncio.run(scheduler.check_credentials_job())
    assert persisted == [('rspamd_password', True, 'fp-rspamd')]
    assert status.call_args.args[1:] == ('failed', 'The Read-Write API key could not be checked. See Settings > Mailcow.')


def test_status_and_a_manual_run_know_the_job(monkeypatch):
    monkeypatch.setattr(rs.mailcow_api, 'headers_rw', None)
    monkeypatch.setattr(type(rs.settings._inner), 'is_rspamd_configured', property(lambda self: False))
    assert rs._job_off_reason('check_credentials') == ('Needs the Read-Write API key or the Rspamd password', 'mailcow')
    assert rs._job_cannot_run('check_credentials') == 'Needs the Read-Write API key or the Rspamd password'
    monkeypatch.setattr(type(rs.settings._inner), 'is_rspamd_configured', property(lambda self: True))
    assert rs._job_off_reason('check_credentials') is None
    assert 'check_credentials' in scheduler.job_status


def test_a_manual_run_keeps_a_rejection_on_status(monkeypatch):
    persisted, status = _checks(monkeypatch, rw={'configured': True, 'valid': False, 'error': 'rejected'})
    # The manual run wrapper writes success over any job that does not say it set its status
    assert asyncio.run(scheduler.check_credentials_job()) == scheduler.JOB_STATUS_SET
    assert status.call_args.args[1] == 'failed'


def test_a_check_of_a_key_changed_meanwhile_is_not_kept(monkeypatch):
    """The key is changed (and its own check saved) while the scheduled check
    still waits for mailcow: the late answer is about the old key."""
    current = {'fp': 'old'}

    async def slow_reject():
        current['fp'] = 'new'  # saved in Settings while this check waited
        return {'configured': True, 'valid': False, 'error': 'rejected'}

    persisted, status = _checks(monkeypatch, rw=ACCEPTED)
    rs._CREDENTIAL_CHECKS['mailcow_rw_key'].update(fingerprint=lambda: current['fp'], check=slow_reject)
    asyncio.run(scheduler.check_credentials_job())
    assert persisted == [], 'the result of the new key stays'
    status.assert_called_with('check_credentials', 'success')


def test_the_compare_and_the_save_are_one_step(monkeypatch):
    """The key changes after the check answered, while its save waits: the
    old answer is not written over the check of the new key."""
    import threading
    current = {'fp': 'old'}
    persisted, status = _checks(monkeypatch, rw=ACCEPTED)
    rs._CREDENTIAL_CHECKS['mailcow_rw_key']['fingerprint'] = lambda: current['fp']
    out = {}
    rs._CREDENTIAL_SAVE_LOCK.acquire()
    try:
        worker = threading.Thread(target=lambda: out.update(result=asyncio.run(rs._validate_credential('mailcow_rw_key'))))
        worker.start()
        worker.join(0.5)
        assert worker.is_alive(), 'the save waits for the lock'
        current['fp'] = 'new'  # saved in Settings, and its own check saved, meanwhile
    finally:
        rs._CREDENTIAL_SAVE_LOCK.release()
    worker.join(5)
    assert out['result'].get('stale') is True and persisted == []


def test_an_older_run_finishing_late_leaves_the_newer_runs_status(monkeypatch):
    """A scheduled run still waits for mailcow when a manual run starts and
    finds the key rejected: the late run does not write success over it."""
    gate = {}
    persisted, status = _checks(monkeypatch, rw=ACCEPTED)
    answers = iter(['slow', 'rejected'])

    async def check():
        if next(answers) == 'slow':
            await gate['release'].wait()
            return ACCEPTED
        return {'configured': True, 'valid': False, 'error': 'rejected'}

    rs._CREDENTIAL_CHECKS['mailcow_rw_key']['check'] = check

    async def run():
        gate['release'] = asyncio.Event()
        older = asyncio.create_task(scheduler.check_credentials_job())
        await asyncio.sleep(0)
        await scheduler.check_credentials_job()   # the newer run, finished first
        gate['release'].set()
        await older

    asyncio.run(run())
    assert [c.args[1] for c in status.call_args_list] == ['running', 'running', 'failed']
