"""A message between two locally hosted domains is only 'internal' when it
also ENTERED the server locally. A hosted sender domain whose mail arrives
from an outside relay (for example through Microsoft 365) is inbound - the
old rule looked at the domains alone and called it internal."""
import uuid
from datetime import datetime, timedelta

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app import correlation as corr_mod
from app.correlation import correlate_rspamd_log

LOCAL_A = 'origin-a.example'
LOCAL_B = 'origin-b.example'
MARK = uuid.uuid4().hex[:8]


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _cleanup():
    from app.database import get_db_context
    from app.models import MessageCorrelation, PostfixLog, RspamdLog
    with get_db_context() as db:
        db.query(MessageCorrelation).filter(
            MessageCorrelation.message_id.like(f'%{MARK}%')).delete(synchronize_session=False)
        db.query(PostfixLog).filter(
            PostfixLog.message_id.like(f'%{MARK}%')).delete(synchronize_session=False)
        db.query(RspamdLog).filter(
            RspamdLog.message_id.like(f'%{MARK}%')).delete(synchronize_session=False)
        db.commit()


@pytest.fixture()
def env(monkeypatch):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import init_db
    init_db()
    _cleanup()
    monkeypatch.setattr(corr_mod, 'is_local_domain',
                        lambda d: d in (LOCAL_A, LOCAL_B))
    yield
    _cleanup()


def _seed_and_correlate(db, tag, ip, has_auth, user='unknown'):
    """One local-to-local delivery via dovecot, entering from the given IP."""
    from app.models import PostfixLog, RspamdLog
    now = datetime.utcnow()
    msgid = f'{tag}-{MARK}@relay.example'
    queue = uuid.uuid4().hex[:11].upper()
    db.add(PostfixLog(time=now, program='postfix/lmtp', message=f'{queue}: seeded',
                      queue_id=queue, message_id=msgid,
                      sender=f'user@{LOCAL_A}', recipient=f'someone@{LOCAL_B}',
                      status='sent', relay='dovecot'))
    # Ingest classifies inbound/outbound (detect_direction); the internal
    # override under test runs later, during correlation
    ingest_direction = 'outbound' if (has_auth or user != 'unknown') else 'inbound'
    rlog = RspamdLog(time=now - timedelta(seconds=1), message_id=msgid,
                     sender_smtp=f'user@{LOCAL_A}',
                     recipients_smtp=[f'someone@{LOCAL_B}'],
                     action='no action', is_spam=False,
                     direction=ingest_direction,
                     ip=ip, user=user, has_auth=has_auth)
    db.add(rlog)
    db.commit()
    return correlate_rspamd_log(db, rlog)


def test_external_origin_is_not_internal(env):
    """The reported case: local sender domain, local recipient, dovecot
    delivery - but the mail arrived from a public relay address."""
    from app.database import get_db_context
    with get_db_context() as db:
        c = _seed_and_correlate(db, 'ext', ip='212.199.162.78', has_auth=False)
        assert c.direction != 'internal', \
            'mail entering from an external address must not be internal'
        assert c.direction == 'inbound'


def test_authenticated_submission_is_internal(env):
    from app.database import get_db_context
    with get_db_context() as db:
        c = _seed_and_correlate(db, 'auth', ip='84.94.10.20', has_auth=True,
                                user=f'user@{LOCAL_A}')
        assert c.direction == 'internal'


def test_private_origin_is_internal(env):
    from app.database import get_db_context
    with get_db_context() as db:
        c = _seed_and_correlate(db, 'lan', ip='172.22.1.248', has_auth=False)
        assert c.direction == 'internal'


def test_tainted_stored_internal_is_rederived(env):
    """Rspamd rows classified 'internal' by the old rule keep that value in
    the database; a re-correlation must not inherit it blindly."""
    from app.database import get_db_context
    from app.models import PostfixLog, RspamdLog
    with get_db_context() as db:
        now = datetime.utcnow()
        msgid = f'tainted-{MARK}@relay.example'
        queue = uuid.uuid4().hex[:11].upper()
        db.add(PostfixLog(time=now, program='postfix/lmtp', message=f'{queue}: seeded',
                          queue_id=queue, message_id=msgid,
                          sender=f'user@{LOCAL_A}', recipient=f'someone@{LOCAL_B}',
                          status='sent', relay='dovecot'))
        rlog = RspamdLog(time=now, message_id=msgid,
                         sender_smtp=f'user@{LOCAL_A}',
                         recipients_smtp=[f'someone@{LOCAL_B}'],
                         action='no action', is_spam=False,
                         direction='internal',
                         ip='212.199.162.78', user='unknown', has_auth=False)
        db.add(rlog)
        db.commit()
        c = correlate_rspamd_log(db, rlog)
        assert c.direction == 'inbound'
        assert rlog.direction == 'inbound'


def test_origin_helper_edge_cases():
    from app.correlation import origin_is_local
    class Stub:
        has_auth = False
        user = 'unknown'
        ip = None
    assert origin_is_local(None) is True          # never passed rspamd
    assert origin_is_local(Stub()) is True        # no ip recorded
    s = Stub(); s.ip = '127.0.0.1'
    assert origin_is_local(s) is True
    s = Stub(); s.ip = 'not-an-ip'
    assert origin_is_local(s) is False
