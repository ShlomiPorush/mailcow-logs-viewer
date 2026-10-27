"""What the automatic bounce and stuck-queue handling may change.

- A block a person set (an administrator's entry, or an automatic one made
  permanent by hand) keeps its reason and expiry: a bounce only counts.
- A block a person turned off stays off, and its queued mail stays.
- Mail to a domain hosted on this mailcow is inbound: its delivery failures
  never block the address or delete its mail, and the jobs wait until every
  domain of this mailcow is known.

Fictional domains only.
"""
import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, Mock

import pytest

MARK = uuid.uuid4().hex[:6]
HOSTED = f'hosted-{MARK}.test'
REMOTE = f'remote-{MARK}.test'


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


@pytest.fixture
def env(monkeypatch):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app import config
    from app.config import settings
    from app.database import get_db_context, init_db
    from app.models import PostfixLog, SpamSuppression
    import app.scheduler as sch

    init_db()
    monkeypatch.setattr(type(settings._inner), 'is_feature_enabled', lambda self, name: True)
    for key, value in {
        'suppression_enabled': True, 'suppression_auto_detect': True, 'suppression_rspamd_sync': True,
        'suppression_whitelist_domains': '', 'suppression_hard_bounce_action': 'suppress',
        'suppression_soft_bounce_action': 'count', 'suppression_soft_bounce_threshold': 3,
        'suppression_base_expiry_days': 7, 'suppression_max_expiry_days': 90,
        'queue_cleanup_enabled': False, 'queue_cleanup_threshold_minutes': 60, 'rspamd_password': '',
    }.items():
        monkeypatch.setattr(settings._inner, key, value)
    monkeypatch.setattr(sch.mailcow_api, 'headers_rw', None)   # no queue calls
    monkeypatch.setattr(sch, '_spam_blocks_loaded', AsyncMock(return_value=True))
    monkeypatch.setattr(sch, 'update_job_status', Mock())
    monkeypatch.setattr(config, '_cached_active_domains', [HOSTED])

    def wipe():
        with get_db_context() as db:
            db.query(SpamSuppression).filter(SpamSuppression.email.like(f'%{MARK}%')).delete(synchronize_session=False)
            db.query(PostfixLog).filter(PostfixLog.recipient.like(f'%{MARK}%')).delete(synchronize_session=False)
            db.commit()

    class Env:
        sch_ = sch

        def block(self, email, source='manual', reason='manual', expires_at=None, active=True):
            with get_db_context() as db:
                db.add(SpamSuppression(email=email, type='email', reason=reason, source=source, active=active,
                                       synced_to_rspamd=True, expires_at=expires_at, bounce_count=0,
                                       hard_bounce_count=0, soft_bounce_count=0))
                db.commit()

        def change(self, email, **fields):
            """A change on the Suppressions page."""
            from app.routers.suppressions import SuppressionUpdateRequest, update_suppression
            with get_db_context() as db:
                row = db.query(SpamSuppression).filter(SpamSuppression.email == email).one()
                update_suppression(row.id, SuppressionUpdateRequest(**fields), db)

        def bounce(self, email, dsn='5.1.1', program='postfix/smtp'):
            with get_db_context() as db:
                now = datetime.utcnow()
                db.add(PostfixLog(time=now, created_at=now, program=program, priority='info',
                                  message=f'{MARK}: to=<{email}>, status=bounced', queue_id=f'Q{uuid.uuid4().hex[:8]}',
                                  recipient=email, status='bounced' if dsn.startswith('5.') else 'deferred', dsn=dsn))
                db.commit()

        def detect(self):
            asyncio.run(sch.detect_suppressions_job())

        def fail(self, email, path):
            """A permanent bounce read by the detection, or a stuck message stored by the cleanup."""
            if path == 'bounce':
                self.bounce(email)
                self.detect()
            else:
                self.stuck(email)

        def stuck(self, email):
            """The stuck-queue cleanup storing the block for one stuck message."""
            return sch._store_deferred_suppressions_worker([{
                'email': email, 'queue_id': f'Q{uuid.uuid4().hex[:8]}', 'sender': f'a@{REMOTE}',
                'arrived': datetime.utcnow() - timedelta(hours=2), 'reason': 'connect timed out'}])

        def row(self, email):
            with get_db_context() as db:
                s = db.query(SpamSuppression).filter(SpamSuppression.email == email).first()
                if s is not None:
                    db.expunge(s)
                return s

        def outcomes(self, email):
            from app.models import SuppressionEvent
            with get_db_context() as db:
                row = db.query(SpamSuppression).filter(SpamSuppression.email == email).one()
                return [e.outcome for e in db.query(SuppressionEvent).filter(
                    SuppressionEvent.suppression_id == row.id,
                    SuppressionEvent.kind.in_(['hard_bounce', 'soft_bounce', 'deferred_stuck'])).order_by(SuppressionEvent.id)]

    wipe()
    yield Env()
    wipe()


# ---------- a block a person set keeps its reason and expiry ----------

@pytest.mark.parametrize('path', ['bounce', 'stuck'])
def test_an_administrators_permanent_block_stays_permanent(env, path):
    email = f'blocked-{path}@{REMOTE}'
    env.block(email)
    env.fail(email, path)

    row = env.row(email)
    assert (row.source, row.reason, row.active, row.expires_at) == ('manual', 'manual', True, None)
    assert row.bounce_count == 1, 'the bounce still counts'
    assert env.outcomes(email) == ['kept']
    env.sch_._expire_suppressions_sync()
    assert env.row(email).active


@pytest.mark.parametrize('path', ['bounce', 'stuck'])
def test_an_automatic_block_made_permanent_by_hand_stays_permanent(env, path):
    email = f'made-permanent-{path}@{REMOTE}'
    env.block(email, source='auto', reason='hard_bounce', expires_at=datetime.utcnow() + timedelta(days=7))
    env.change(email, expires_at='null')
    env.fail(email, path)

    row = env.row(email)
    assert (row.reason, row.active, row.expires_at) == ('hard_bounce', True, None)


def test_a_bounce_never_brings_a_longer_expiry_closer(env):
    email = f'long@{REMOTE}'
    later = datetime.utcnow() + timedelta(days=200)
    env.block(email, source='auto', reason='hard_bounce', expires_at=later)
    env.bounce(email)
    env.detect()
    assert env.row(email).expires_at == later


@pytest.mark.parametrize('path', ['bounce', 'stuck'])
def test_a_block_turned_off_by_hand_stays_off_and_its_mail_stays(env, path):
    email = f'turned-off-{path}@{REMOTE}'
    env.block(email, source='auto', reason='hard_bounce', expires_at=datetime.utcnow() + timedelta(days=7))
    env.change(email, active=False)
    env.fail(email, path)

    row = env.row(email)
    assert row.active is False and row.bounce_count == 1
    assert env.outcomes(email) == ['kept']
    assert env.sch_._protected_now({email, f'other@{REMOTE}'}) == {email}


def test_a_block_that_ran_out_is_blocked_again(env):
    """Automatic handling of a block nobody touched works as before."""
    email = f'ran-out@{REMOTE}'
    env.block(email, source='manual', expires_at=datetime.utcnow() - timedelta(days=1), active=False)
    env.bounce(email)
    env.detect()
    row = env.row(email)
    assert row.active and row.reason == 'hard_bounce' and row.expires_at > datetime.utcnow()
    assert env.outcomes(email) == ['activated']


# ---------- mail to a domain hosted here ----------

@pytest.mark.parametrize('program', ['postfix/lmtp', 'postfix/smtp'])
def test_a_failed_delivery_to_a_hosted_mailbox_blocks_nothing(env, program):
    hosted = f'full-mailbox@{HOSTED}'
    remote = f'gone@{REMOTE}'
    env.bounce(hosted, dsn='5.2.2', program=program)
    env.bounce(remote)
    env.detect()
    assert env.row(hosted) is None
    assert env.row(remote).active, 'a remote address still gets blocked'


def test_a_local_delivery_line_blocks_nothing_whatever_its_address(env):
    email = f'someone@{REMOTE}'
    env.bounce(email, dsn='5.2.2', program='postfix/lmtp')
    env.detect()
    assert env.row(email) is None


def test_the_stuck_queue_block_asks_again_for_hosted_domains(env):
    """The domain list can change between picking the message and storing its block."""
    env.stuck(f'inbound@{HOSTED}')
    assert env.row(f'inbound@{HOSTED}') is None


def _no_alias_side_effects(monkeypatch):
    """A domain sync here changes nothing other tests read."""
    from app import config, scheduler
    monkeypatch.setattr(config, '_cached_hosted_domains', set())
    monkeypatch.setattr(scheduler, '_persist_local_domain_aliases', lambda alias_map: None)
    monkeypatch.setattr('app.services.alias_domains.set_cached_alias_domain_map', lambda alias_map: None)


def test_detection_waits_until_every_domain_is_known(env, monkeypatch):
    from app import config
    email = f'later@{REMOTE}'
    env.bounce(email)
    monkeypatch.setattr(config, '_cached_domains_complete', None)
    monkeypatch.setattr(env.sch_, 'sync_local_domains', AsyncMock(return_value=False))   # mailcow does not answer
    env.detect()
    assert env.row(email) is None
    env.sch_.sync_local_domains.assert_awaited()
    env.sch_.update_job_status.assert_called_with('detect_suppressions', 'failed', env.sch_._DOMAINS_WAIT)

    monkeypatch.setattr(config, '_cached_domains_complete', env.sch_.mailcow_api.base_url)
    env.detect()
    assert env.row(email).active, 'the line is read once the domains are known'


def test_only_a_full_domain_sync_counts_as_every_domain_known(monkeypatch):
    from app import config, scheduler
    _no_alias_side_effects(monkeypatch)
    url = scheduler.mailcow_api.base_url
    monkeypatch.setattr(config, '_cached_active_domains', None)
    config.set_cached_active_domains([HOSTED])   # the startup load: primary domains only
    assert not config.local_domains_complete(url)

    monkeypatch.setattr(scheduler.mailcow_api, 'get_domains', AsyncMock(return_value=[{'domain_name': HOSTED, 'active': 1}]))
    monkeypatch.setattr(scheduler.mailcow_api, 'get_alias_domain_map', AsyncMock(side_effect=RuntimeError('down')))
    monkeypatch.setattr(scheduler, 'update_job_status', Mock())
    asyncio.run(scheduler.sync_local_domains())
    assert not config.local_domains_complete(url), 'alias domains failed to load'

    monkeypatch.setattr(scheduler.mailcow_api, 'get_alias_domain_map', AsyncMock(return_value={}))
    asyncio.run(scheduler.sync_local_domains())
    assert config.local_domains_complete(url)
    assert not config.local_domains_complete('https://other-mailcow.example.com'), 'read from another mailcow'


def test_a_mailcow_changed_during_the_sync_leaves_the_list_incomplete(monkeypatch):
    from app import config, scheduler
    _no_alias_side_effects(monkeypatch)
    monkeypatch.setattr(config, '_cached_active_domains', None)
    monkeypatch.setattr(config, '_cached_domains_complete', None)
    monkeypatch.setattr(scheduler, 'update_job_status', Mock())

    async def domains(**kwargs):
        monkeypatch.setattr(scheduler.mailcow_api, 'base_url', 'https://other-mailcow.example.com')
        return [{'domain_name': HOSTED, 'active': 1}]
    monkeypatch.setattr(scheduler.mailcow_api, 'get_domains', domains)
    monkeypatch.setattr(scheduler.mailcow_api, 'get_alias_domain_map', AsyncMock(return_value={}))
    asyncio.run(scheduler.sync_local_domains())
    assert not config.local_domains_complete('https://other-mailcow.example.com')


@pytest.mark.parametrize('answer,expected', [
    ([], {}), ({}, {}),
    ([{'alias_domain': f'Alias.{HOSTED}', 'target_domain': HOSTED, 'active': 1}], {f'alias.{HOSTED}': HOSTED}),
    ({'type': 'error', 'msg': 'access denied'}, None),
])
def test_an_alias_domain_answer_that_is_not_a_list_of_them_is_an_error(monkeypatch, answer, expected):
    from app.mailcow_api import MailcowAPIError, mailcow_api
    monkeypatch.setattr(mailcow_api, '_make_request', AsyncMock(return_value=answer))
    if expected is None:
        with pytest.raises(MailcowAPIError):
            asyncio.run(mailcow_api.get_alias_domain_map())
    else:
        assert asyncio.run(mailcow_api.get_alias_domain_map()) == expected


# ---------- the stuck-queue cleanup ----------

OLD = datetime.now(timezone.utc).timestamp() - 7200


def _stuck_item(queue_id, *recipients):
    return {'queue_id': queue_id, 'queue_name': 'deferred', 'arrival_time': OLD, 'recipients': list(recipients)}


@pytest.fixture
def queue(monkeypatch):
    from app import config
    from app.config import settings
    import app.scheduler as sch
    monkeypatch.setattr(type(settings._inner), 'is_feature_enabled', lambda self, name: True)
    for key, value in {'suppression_enabled': True, 'suppression_rspamd_sync': True, 'queue_cleanup_enabled': True,
                       'queue_cleanup_block': True, 'queue_cleanup_threshold_minutes': 30,
                       'suppression_whitelist_domains': '', 'rspamd_password': ''}.items():
        monkeypatch.setattr(settings._inner, key, value)
    monkeypatch.setattr(config, '_cached_active_domains', [HOSTED])
    monkeypatch.setattr(sch.mailcow_api, 'headers_rw', {'X-API-Key': 'test-key'})
    monkeypatch.setattr(sch, 'update_job_status', Mock())
    monkeypatch.setattr(sch, '_spam_blocks_loaded', AsyncMock(return_value=True))
    monkeypatch.setattr(sch, '_protected_now', lambda emails: set())
    monkeypatch.setattr(sch, '_blocked_now', lambda emails: set(emails))
    monkeypatch.setattr(sch.mailcow_api, 'delete_queue', AsyncMock(return_value=[{'type': 'success'}]))
    stored = []
    monkeypatch.setattr(sch, '_store_deferred_suppressions_worker',
                        lambda items, uncovered=None: stored.extend(i['email'] for i in items) or len(items))
    monkeypatch.setattr(sch.mailcow_api, 'get_queue', AsyncMock(return_value=[
        _stuck_item('INBOUND', f'user@{HOSTED} (lost connection with dovecot)'),
        _stuck_item('MIXED', f'user@{HOSTED}', f'user@{REMOTE}'),
        _stuck_item('OUTBOUND', f'user@{REMOTE} (connect timed out)'),
    ]))
    return sch, stored


def test_stuck_mail_to_a_hosted_mailbox_stays_in_the_queue_unblocked(queue):
    sch, stored = queue
    asyncio.run(sch.cleanup_deferred_queue_job())
    assert stored == [f'user@{REMOTE}']
    sch.mailcow_api.delete_queue.assert_awaited_once_with(['OUTBOUND'])


def test_the_cleanup_waits_until_every_domain_is_known(queue, monkeypatch):
    from app import config
    sch, stored = queue
    monkeypatch.setattr(config, '_cached_domains_complete', 'https://other-mailcow.example.com')
    monkeypatch.setattr(sch, 'sync_local_domains', AsyncMock(return_value=False))
    asyncio.run(sch.cleanup_deferred_queue_job())
    assert stored == []
    sch.mailcow_api.delete_queue.assert_not_awaited()
    sch.update_job_status.assert_called_with('cleanup_deferred_queue', 'failed', sch._DOMAINS_WAIT)


def test_mail_to_a_domain_turned_off_in_mailcow_stays_in_the_queue(queue, monkeypatch):
    """Mail it accepted while it was on can still wait in the queue."""
    from app import config
    sch, stored = queue
    _no_alias_side_effects(monkeypatch)
    paused = f'paused-{MARK}.test'
    monkeypatch.setattr(sch.mailcow_api, 'get_domains', AsyncMock(return_value=[
        {'domain_name': HOSTED, 'active': 1}, {'domain_name': paused, 'active': 0}]))
    monkeypatch.setattr(sch.mailcow_api, 'get_alias_domain_map', AsyncMock(return_value={}))
    asyncio.run(sch.sync_local_domains())
    assert config.get_cached_active_domains() == [HOSTED], 'direction classification is unchanged'

    monkeypatch.setattr(sch.mailcow_api, 'get_queue', AsyncMock(return_value=[
        _stuck_item('PAUSED', f'user@{paused}'), _stuck_item('OUTBOUND', f'user@{REMOTE}')]))
    asyncio.run(sch.cleanup_deferred_queue_job())
    assert stored == [f'user@{REMOTE}']
    sch.mailcow_api.delete_queue.assert_awaited_once_with(['OUTBOUND'])


def test_a_mailcow_changed_before_the_queue_is_read_blocks_and_deletes_nothing(queue, monkeypatch):
    sch, stored = queue
    items = sch.mailcow_api.get_queue.return_value

    async def from_another_mailcow():
        monkeypatch.setattr(sch.mailcow_api, 'base_url', 'https://other-mailcow.example.com')
        return items
    monkeypatch.setattr(sch.mailcow_api, 'get_queue', from_another_mailcow)
    asyncio.run(sch.cleanup_deferred_queue_job())
    assert stored == []
    sch.mailcow_api.delete_queue.assert_not_awaited()


def test_a_mailcow_changed_before_the_deletion_deletes_nothing(queue, monkeypatch):
    sch, stored = queue

    def changed_meanwhile(items, blocking):
        monkeypatch.setattr(sch.mailcow_api, 'base_url', 'https://other-mailcow.example.com')
        return list(items)
    monkeypatch.setattr(sch, '_cleanup_deletable', changed_meanwhile)
    asyncio.run(sch.cleanup_deferred_queue_job())
    sch.mailcow_api.delete_queue.assert_not_awaited()
