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
