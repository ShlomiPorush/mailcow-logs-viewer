"""Every shape the Messages calls can answer with, so the contract check (conftest.py,
contract.py) sees each one: a message with all its logs (Rspamd with symbols,
Postfix lines, a Dovecot line, a Netfilter event, another delivery leg), an
unknown message (404), a bad cursor (422 with a string) and a bad parameter
(422 with FastAPI's list), and a failure (500)."""
import uuid
from datetime import datetime, timedelta

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app.config import settings  # noqa: E402

MARK = uuid.uuid4().hex[:8]
MSGID = f'answers-{MARK}@example.com'
# A documentation address of its own per run, so no other row shares it
IP = f'198.51.100.{int(MARK, 16) % 254 + 1}'


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


@pytest.fixture()
def env(monkeypatch):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    for key in ('auth_enabled', 'basic_auth_enabled', 'oauth2_enabled'):
        monkeypatch.setattr(settings._inner, key, False)
    from app.database import get_db_context, init_db
    from app.models import MessageCorrelation, NetfilterLog, PostfixLog, RawServiceLog, RspamdLog
    init_db()
    now = datetime.utcnow().replace(microsecond=0)
    with get_db_context() as db:
        rspamd = RspamdLog(time=now, message_id=MSGID, sender_smtp=f'a@{MARK}.example', ip=IP,
                           recipients_smtp=[f'b@{MARK}.example'], score=3.2, required_score=15.0,
                           action='no action', is_spam=False, direction='inbound', user='',
                           symbols={'DMARC_POLICY_ALLOW': {'score': -0.5, 'options': ['example.com']}},
                           has_auth=False, size=1234)
        db.add(rspamd)
        db.flush()
        queue = f'Q{MARK.upper()}'
        db.add(PostfixLog(time=now, program='postfix/smtpd', priority='info', queue_id=queue,
                          message=f'{queue}: client=mx.example[{IP}]'))
        db.add(PostfixLog(time=now + timedelta(seconds=1), program='postfix/lmtp', priority='info', queue_id=queue,
                          recipient=f'b@{MARK}.example', status='sent', relay='dovecot', delay=0.4, dsn='2.0.0',
                          message=f'{queue}: to=<b@{MARK}.example>, status=sent'))
        netfilter = NetfilterLog(time=now - timedelta(minutes=5), ip=IP, username=f'b@{MARK}.example',
                                 auth_method='SASL', action='warning', attempts_left=9, message='failed login')
        db.add(netfilter)
        db.add(RawServiceLog(service='dovecot', time=now + timedelta(seconds=2), message_hash=uuid.uuid4().hex,
                             raw_data={'message': f'lmtp(b@{MARK}.example): msgid=<{MSGID}>: saved mail to INBOX',
                                       'priority': 'info'}))
        first = MessageCorrelation(correlation_key=uuid.uuid4().hex, message_id=MSGID, queue_id=queue,
                                   rspamd_log_id=rspamd.id, sender=f'a@{MARK}.example',
                                   recipient=f'b@{MARK}.example', direction='inbound', final_status='delivered',
                                   dovecot_status='stored', dovecot_mailbox='INBOX', is_complete=True,
                                   first_seen=now, last_seen=now, created_at=now)
        forward = MessageCorrelation(correlation_key=uuid.uuid4().hex, message_id=MSGID,
                                     sender=f'b@{MARK}.example', recipient=f'c@{MARK}.example',
                                     direction='outbound', final_status='deferred',
                                     first_seen=now + timedelta(seconds=5), created_at=now)
        db.add_all([first, forward])
        db.commit()
        keys = (first.correlation_key, forward.correlation_key)
        netfilter_id = netfilter.id
    from fastapi.testclient import TestClient
    from app.main import app
    yield TestClient(app), keys
    with get_db_context() as db:
        db.query(MessageCorrelation).filter(MessageCorrelation.message_id == MSGID).delete(synchronize_session=False)
        db.query(RspamdLog).filter(RspamdLog.message_id == MSGID).delete(synchronize_session=False)
        db.query(PostfixLog).filter(PostfixLog.queue_id == f'Q{MARK.upper()}').delete(synchronize_session=False)
        db.query(NetfilterLog).filter(NetfilterLog.id == netfilter_id).delete(synchronize_session=False)
        db.query(RawServiceLog).filter(RawServiceLog.raw_data['message'].astext.like(f'%{MSGID}%')).delete(
            synchronize_session=False)
        db.commit()


def test_a_message_with_every_log(env):
    client, (key, _) = env
    payload = client.get(f'/api/message/{key}/details').json()
    assert payload['rspamd']['symbols']['DMARC_POLICY_ALLOW']['score'] == -0.5
    assert payload['dovecot']['logs'][0]['verdict'] == 'stored'
    assert any(e['username'] == f'b@{MARK}.example' and e['attempts_left'] == 9 for e in payload['netfilter'])
    assert payload['related_deliveries'][0]['final_status'] == 'deferred'
    assert payload['postfix'][-1]['recipient'] == f'b@{MARK}.example'
    assert set(payload['postfix_by_recipient']) == {'_system', f'b@{MARK}.example'}


def test_the_list_and_its_counts(env):
    client, _ = env
    page = client.get(f'/api/messages?search={MSGID}&limit=1').json()
    assert page['total'] == 1 and page['data'][0]['spam_score'] == 3.2
    assert client.get(f'/api/messages/facets?search={MSGID}&since=today:2020-01-01').json()['time']['today'] == 1
    assert client.get(f"/api/messages/new?search={MSGID}&after_id={page['watermark']}").json()['count'] == 0


def test_an_unknown_message(env):
    client, _ = env
    assert client.get(f'/api/message/no-such-{MARK}/details').status_code == 404


def test_a_bad_cursor_and_a_bad_parameter(env):
    client, _ = env
    bad_cursor = client.get('/api/messages?cursor=not-a-cursor')
    assert bad_cursor.status_code == 422 and bad_cursor.json() == {'detail': 'Invalid cursor'}
    bad_limit = client.get('/api/messages?limit=0')
    assert bad_limit.status_code == 422 and isinstance(bad_limit.json()['detail'], list)


@pytest.mark.parametrize('path', ['/api/messages', '/api/messages/facets', '/api/messages/new?after_id=0',
                                  '/api/message/x/details'])
def test_a_failure(env, monkeypatch, path):
    from fastapi.testclient import TestClient
    from app.main import app
    from app.routers import messages

    def broken(*args, **kwargs):
        raise RuntimeError('database gone')

    monkeypatch.setattr(messages, '_filtered_messages_query', broken)
    monkeypatch.setattr(messages, 'MessageCorrelation', None)
    response = TestClient(app, raise_server_exceptions=False).get(path)
    assert response.status_code == 500
    assert response.json() == {'detail': 'Internal server error'}
