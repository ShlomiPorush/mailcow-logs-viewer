"""Domain aliases (issue #92): user@alias.tld is the same mailbox as
user@target.tld. The mapping is fetched from mailcow, persisted, and used by
Mailbox Statistics attribution, the domain filter, and the Domains page."""
import asyncio
import uuid
from datetime import datetime, timedelta

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app.config import settings
from app.services import alias_domains as ad

TARGET = 'primary.example'
ALIAS = 'mirror.example'
USER = f'user-{uuid.uuid4().hex[:8]}'


# ---------- pure unit tests (no network, no database) ----------

def test_mailcow_map_parsing(monkeypatch):
    from app.mailcow_api import MailcowAPI
    api = MailcowAPI()

    async def fake(endpoint, method='GET', **kw):
        assert endpoint == '/api/v1/get/alias-domain/all'
        return [
            {'alias_domain': 'Mirror.Example', 'target_domain': 'Primary.Example', 'active': 1},
            {'alias_domain': 'off.example', 'target_domain': 'primary.example', 'active': 0},
            {'alias_domain': 'broken.example', 'active': 1},   # no target - skipped
        ]
    monkeypatch.setattr(api, '_make_request', fake)
    assert asyncio.run(api.get_alias_domain_map()) == {'mirror.example': 'primary.example'}


def test_expand_address_builds_alias_variants():
    mapping = {'mirror.example': 'primary.example', 'other.example': 'primary.example'}
    assert ad.expand_address('User@Primary.Example', mapping) == [
        'user@mirror.example', 'user@other.example']
    assert ad.expand_address('user@unrelated.example', mapping) == []
    assert ad.expand_address('not-an-address', mapping) == []


def test_expand_addresses_deduplicates():
    mapping = {'mirror.example': 'primary.example'}
    out = ad.expand_addresses(['a@primary.example', 'A@PRIMARY.EXAMPLE', 'b@primary.example'], mapping)
    assert out == ['a@mirror.example', 'b@mirror.example']


# ---------- database-backed attribution tests ----------

def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _cleanup():
    from app.database import get_db_context
    from app.models import (MessageCorrelation, MailboxStatistics,
                            AliasStatistics, SystemSetting)
    with get_db_context() as db:
        db.query(MessageCorrelation).filter(
            MessageCorrelation.sender.like(f'%@{TARGET}') |
            MessageCorrelation.sender.like(f'%@{ALIAS}') |
            MessageCorrelation.recipient.like(f'%@{ALIAS}')).delete(synchronize_session=False)
        db.query(MailboxStatistics).filter(
            MailboxStatistics.domain.in_([TARGET, ALIAS])).delete(synchronize_session=False)
        db.query(AliasStatistics).filter(
            AliasStatistics.domain.in_([TARGET, ALIAS])).delete(synchronize_session=False)
        db.query(SystemSetting).filter(
            SystemSetting.key == ad.ALIAS_DOMAIN_MAP_KEY).delete(synchronize_session=False)
        db.commit()


@pytest.fixture()
def env():
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import init_db, get_db_context
    from app.models import MailboxStatistics, MessageCorrelation
    init_db()
    _cleanup()
    now = datetime.utcnow()
    with get_db_context() as db:
        ad.persist_alias_domain_map(db, {ALIAS: TARGET})
        db.add(MailboxStatistics(username=f'{USER}@{TARGET}', domain=TARGET, active=True))
        # 2 messages sent as the primary address, 3 sent as the alias-domain
        # address, 1 received at the alias-domain address
        for k in range(2):
            db.add(MessageCorrelation(
                correlation_key=uuid.uuid4().hex, message_id=f'<p{k}-{uuid.uuid4().hex}@{TARGET}>',
                sender=f'{USER}@{TARGET}', recipient='rcpt@remote.invalid',
                direction='outbound', final_status='delivered',
                first_seen=now - timedelta(minutes=k + 1), last_seen=now, created_at=now))
        for k in range(3):
            db.add(MessageCorrelation(
                correlation_key=uuid.uuid4().hex, message_id=f'<a{k}-{uuid.uuid4().hex}@{ALIAS}>',
                sender=f'{USER}@{ALIAS}', recipient='rcpt@remote.invalid',
                direction='outbound', final_status='delivered',
                first_seen=now - timedelta(minutes=k + 1), last_seen=now, created_at=now))
        db.add(MessageCorrelation(
            correlation_key=uuid.uuid4().hex, message_id=f'<r-{uuid.uuid4().hex}@remote>',
            sender='someone@remote.invalid', recipient=f'{USER}@{ALIAS}',
            direction='inbound', final_status='delivered',
            first_seen=now - timedelta(minutes=1), last_seen=now, created_at=now))
        db.commit()
    ad.set_cached_alias_domain_map({ALIAS: TARGET})
    yield
    _cleanup()
    ad.set_cached_alias_domain_map({})


def _get_all(domain=None):
    from app.database import get_db_context
    from app.routers.mailbox_stats import get_all_mailbox_stats
    with get_db_context() as db:
        return asyncio.run(get_all_mailbox_stats(
            domain=domain, active_only=False, hide_zero=False, search=None,
            date_range='7days', start_date=None, end_date=None,
            sort_by='sent_total', sort_order='desc', page=1, page_size=100, db=db))


def test_alias_domain_traffic_is_attributed_to_the_mailbox(env):
    """The bug the issue reports: mail sent as user@alias.tld was invisible.
    It must appear on the mailbox user@target.tld as an alias row and count
    into the combined totals exactly once."""
    data = _get_all()
    mb = next(m for m in data['mailboxes'] if m['username'] == f'{USER}@{TARGET}')
    assert mb['combined_sent'] == 5, 'alias-domain sends must count toward the mailbox'
    assert mb['combined_received'] == 1
    row = next(a for a in mb['aliases'] if a['alias_address'] == f'{USER}@{ALIAS}')
    assert row['is_domain_alias'] is True
    assert row['sent_total'] == 3
    assert row['received_total'] == 1
    # the mailbox's own count stays its own - no double counting
    assert mb['mailbox_counts']['sent_total'] == 2


def test_summary_counts_alias_domain_traffic(env):
    from app.database import get_db_context
    from app.routers.mailbox_stats import get_mailbox_stats_summary
    with get_db_context() as db:
        summary = asyncio.run(get_mailbox_stats_summary(
            date_range='7days', start_date=None, end_date=None, db=db))
    assert summary['total_sent'] >= 5
    assert summary['total_received'] >= 1


def test_filtering_by_the_alias_domain_shows_the_target_mailboxes(env):
    data = _get_all(domain=ALIAS)
    assert any(m['username'] == f'{USER}@{TARGET}' for m in data['mailboxes']), \
        'selecting the alias domain must show the mailboxes it delivers to'


def test_domain_dropdown_lists_the_alias_domain(env):
    from app.database import get_db_context
    from app.routers.mailbox_stats import get_mailbox_domains
    with get_db_context() as db:
        result = get_mailbox_domains(db=db)
    by_name = {d['domain']: d for d in result['domains']}
    assert TARGET in by_name
    assert ALIAS in by_name
    assert by_name[ALIAS].get('alias_of') == TARGET


def test_anomaly_local_set_includes_alias_variants(env):
    from app.database import get_db_context
    from app.services.anomaly_service import _local_addresses
    with get_db_context() as db:
        local = _local_addresses(db)
    assert f'{USER}@{TARGET}'.lower() in local
    assert f'{USER}@{ALIAS}'.lower() in local


def test_map_survives_a_process_restart(env):
    """The cache is per-process; a fresh process must reload the persisted map."""
    from app.database import get_db_context
    ad.set_cached_alias_domain_map({})
    ad._cache_loaded_at = 0.0
    with get_db_context() as db:
        assert ad.get_alias_domain_map(db) == {ALIAS: TARGET}
