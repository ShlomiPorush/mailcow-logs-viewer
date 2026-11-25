import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from app import scheduler
from app.config import settings
from app.mailcow_api import MailcowShownError, MailcowWriteUnknownError
from app.services import smtp_abuse_service
from app.services.job_status import job_status
from test_protection_enforce import FakeMailcow, _enforce, _fresh, _trap_hit
from test_protection_rules import SUBNET, SUBNET_IPS, TRAP_IP, _context, _fail, _rules, db  # noqa: F401
from test_rate_limits import (  # noqa: F401
    DOMAIN, MARKER, QUIET, SENDER, _bulk, _fake_client, _limit_of, _set_domain, _set_mailbox, env,
)

NO_ANSWER = [None, '', 'ok', [], {}]
SUCCESS = {'type': 'success', 'msg': 'f2b_modified'}


class Answering(FakeMailcow):
    def __init__(self, reply, **kwargs):
        super().__init__(**kwargs)
        self.reply = reply

    async def edit_fail2ban(self, attrs):
        await super().edit_fail2ban(attrs)
        return self.reply


@pytest.mark.parametrize('answer', NO_ANSWER)
def test_a_ban_mailcow_did_not_confirm_stays_pending(db, answer):
    _trap_hit(db)
    result = _enforce(Answering(answer))
    hit = _fresh(db)[0]
    assert hit.status == 'pending' and 'mailcow did not confirm' in hit.error
    assert not result['banned'] and [f[0] for f in result['failed']] == [TRAP_IP]


def test_an_entry_mailcow_dropped_from_the_list_does_not_undo_the_ban(db):
    _trap_hit(db)
    result = _enforce(Answering([{'type': 'danger', 'msg': ['network_host_invalid', 'not a host']}, SUCCESS]))
    assert [b[0] for b in result['banned']] == [TRAP_IP]
    hit = _fresh(db)[0]
    assert hit.status == 'banned' and hit.owned


def test_a_network_mailcow_refuses_stays_pending_while_the_rest_is_banned(db):
    from app.services import protection_rules
    _rules(db, subnet={'enabled': True, 'threshold': 3, 'window_hours': 24, 'mode': 'enforce'},
           trap={'enabled': True, 'names': ['admin'], 'mode': 'enforce'})
    for ip in SUBNET_IPS[:3]:
        _fail(db, ip, 'someone')
    _fail(db, TRAP_IP, 'admin')
    protection_rules.evaluate(db, _context())
    result = _enforce(Answering([{'type': 'danger', 'msg': ['network_host_invalid', SUBNET]}, SUCCESS]))
    by_ip = {h.ip: h for h in _fresh(db)}
    assert by_ip[SUBNET].status == 'pending' and 'mailcow refuses' in by_ip[SUBNET].error
    assert by_ip[TRAP_IP].status == 'banned'
    assert [f[0] for f in result['failed']] == [SUBNET]


@pytest.mark.parametrize('answer', NO_ANSWER + [[{'type': 'danger', 'msg': 'access denied'}]])
def test_an_undo_mailcow_did_not_confirm_keeps_the_ban(db, answer):
    from app.services import protection_rules
    _trap_hit(db)
    api = FakeMailcow()
    _enforce(api)
    hit = _fresh(db)[0]
    refusing = Answering(answer, blacklist=f'{TRAP_IP}/32')
    with pytest.raises(RuntimeError):
        asyncio.run(protection_rules.undo(refusing, hit.id))
    assert _fresh(db)[0].status == 'banned'


@pytest.mark.parametrize('answer,said', [
    ([{'type': 'danger', 'msg': 'access_denied'}], 'access_denied'),
    ([], 'did not confirm'), (None, 'did not confirm'), ('', 'did not confirm')])
def test_a_rate_limit_mailcow_did_not_set_is_an_error_and_not_stored(env, monkeypatch, answer, said):
    fake = _fake_client(monkeypatch)
    for name in ('edit_rl_mbox', 'edit_rl_domain', 'edit_rl_mboxes', 'edit_rl_domains'):
        setattr(fake, name, AsyncMock(return_value=answer))
    for change in (lambda: _set_mailbox(777, 'd'), lambda: _set_domain(777, 'd'),
                   lambda: _bulk(777, 'd', mailboxes=[SENDER], domains=[DOMAIN])):
        with pytest.raises(HTTPException) as refused:
            change()
        assert refused.value.status_code == 502 and said in refused.value.detail
    assert _limit_of(SENDER) == (100, 'm')


def test_a_bulk_change_keeps_what_mailcow_set_and_skips_the_rest(env, monkeypatch):
    fake = _fake_client(monkeypatch)
    fake.edit_rl_mboxes = AsyncMock(return_value=[
        {'type': 'success', 'msg': ['rl_saved', SENDER]}, {'type': 'danger', 'msg': 'access_denied'}])
    fake.edit_rl_domains = AsyncMock(return_value=[{'type': 'danger', 'msg': 'access_denied'}])
    result = _bulk(777, 'd', mailboxes=[SENDER, QUIET], domains=[DOMAIN])
    assert (result['mailboxes_updated'], result['domains_updated']) == (1, 0)
    assert set(result['skipped']) == {QUIET, DOMAIN}
    assert _limit_of(SENDER) == (777, 'd') and _limit_of(QUIET) == (None, None)


def test_a_bulk_change_of_names_the_server_does_not_know_is_still_no_error(env, monkeypatch):
    fake = _fake_client(monkeypatch)
    result = _bulk(5, 'm', mailboxes=[f'gone-{MARKER}@{DOMAIN}'])
    assert result['skipped'] == [f'gone-{MARKER}@{DOMAIN}'] and fake.calls == []


@pytest.mark.parametrize('answer,error', [
    ([{'type': 'danger', 'msg': 'access_denied'}], MailcowShownError),
    ({'type': 'error', 'msg': 'Cannot edit item'}, MailcowShownError),
    ([], MailcowWriteUnknownError), (None, MailcowWriteUnknownError)])
def test_a_mailbox_mailcow_did_not_block_is_not_recorded_as_blocked(monkeypatch, answer, error):
    recorded = []
    monkeypatch.setattr(smtp_abuse_service.mailcow_api, 'edit_mailbox', AsyncMock(return_value=answer))
    monkeypatch.setattr(smtp_abuse_service, '_revoke_app_passwords', AsyncMock(side_effect=AssertionError))
    monkeypatch.setattr(smtp_abuse_service, 'record_action', lambda *args: recorded.append(args))
    for change in (smtp_abuse_service.block_mailbox('user@example.com', 9),
                   smtp_abuse_service.unblock_mailbox('user@example.com')):
        with pytest.raises(error) as refused:
            asyncio.run(change)
        assert 'Internal' not in str(refused.value)
    assert recorded == []


def test_the_smtp_abuse_job_fails_when_a_mailbox_could_not_be_blocked(monkeypatch):
    monkeypatch.setattr(settings._inner, 'smtp_abuse_enabled', True)
    monkeypatch.setattr(type(smtp_abuse_service.mailcow_api), 'has_rw_key', property(lambda self: True))
    monkeypatch.setattr(smtp_abuse_service, 'find_candidates',
                        lambda: [{'email': 'a@example.com', 'count': 9}, {'email': 'b@example.com', 'count': 9}])

    async def block(email, *args, **kwargs):
        if email == 'a@example.com':
            raise MailcowShownError('mailcow did not disable SMTP for a@example.com: access_denied')
    monkeypatch.setattr(smtp_abuse_service, 'block_mailbox', block)
    assert asyncio.run(scheduler.smtp_abuse_job()) == scheduler.JOB_STATUS_SET
    assert job_status['smtp_abuse']['status'] == 'failed' and 'a@example.com' in job_status['smtp_abuse']['error']
    assert 'b@example.com' not in job_status['smtp_abuse']['error']


def test_a_cancelled_smtp_abuse_job_is_not_a_success(monkeypatch):
    monkeypatch.setattr(settings._inner, 'smtp_abuse_enabled', True)
    monkeypatch.setattr(type(smtp_abuse_service.mailcow_api), 'has_rw_key', property(lambda self: True))
    monkeypatch.setattr(smtp_abuse_service, 'run_abuse_protection', AsyncMock(side_effect=asyncio.CancelledError))
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(scheduler.smtp_abuse_job())
    assert job_status['smtp_abuse']['status'] != 'success'


@pytest.fixture()
def raw_rows(db):
    from app.models import RawServiceLog
    yield
    db.rollback()
    db.query(RawServiceLog).filter(RawServiceLog.message_hash.like(f'{MARKER}%')).delete(synchronize_session=False)
    db.commit()


@pytest.mark.parametrize('service', ['dovecot', 'postfix'])
def test_a_login_stored_while_the_logins_are_read_is_read_next_time(db, raw_rows, service):
    from sqlalchemy import event
    from app.database import engine, get_db_context
    from app.models import PostfixLog, RawServiceLog
    from app.services import protection_rules
    from test_protection_rules import MARKER as RULES_MARKER
    context = protection_rules.ProtectionContext(raw_logs=True)
    assert protection_rules._successful_logins(db, context) == []
    db.commit()
    user = 'late@example.com'

    def row():
        when = datetime.utcnow() - timedelta(minutes=1)
        if service == 'dovecot':
            return RawServiceLog(service='dovecot', time=when, message_hash=f'{MARKER}-late', raw_data={
                'message': f'imap-login: Login: user=<{user}>, method=PLAIN, rip={TRAP_IP}, lip=172.22.1.250, '
                           'mpid=1, TLS, session=<a>'})
        return PostfixLog(time=when, queue_id=RULES_MARKER[:20], program='postfix/smtpd',
                          message=f'ABC123: client=x[{TRAP_IP}], sasl_method=PLAIN, sasl_username={user}')

    table = 'raw_service_logs' if service == 'dovecot' else 'postfix_logs'
    stored = []

    def store_meanwhile(conn, cursor, statement, parameters, ctx, executemany):
        if not stored and statement.startswith('SELECT') and f'FROM {table}' in statement and 'LIKE' in statement:
            stored.append(True)
            with get_db_context() as other:
                other.add(row())
                other.commit()

    event.listen(engine, 'after_cursor_execute', store_meanwhile)
    try:
        assert protection_rules._successful_logins(db, context) == []
    finally:
        event.remove(engine, 'after_cursor_execute', store_meanwhile)
    db.commit()
    assert stored
    assert [login.username for login in protection_rules._successful_logins(db, context)] == [user]
    db.commit()
    assert protection_rules._successful_logins(db, context) == []
