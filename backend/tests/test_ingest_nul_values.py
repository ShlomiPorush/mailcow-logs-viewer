"""One value the database refuses must not cost the rest of a page.

Mail log lines and quarantine items carry text that whoever sends the mail
chooses. PostgreSQL cannot store NUL in a text or JSON column, and each page
of Postfix, Rspamd, Netfilter and raw log lines, and each run's quarantine
rule history, was committed at once: one such value rolled back every row
with it, and the same page failed again on every cycle. NUL is now dropped
before anything reads the entry, and a row the database still refuses is
skipped alone.
"""
import asyncio
import random
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app import raw_logs_worker, scheduler
from app.config import settings

MARK = uuid.uuid4().hex[:8]
# Times of their own, so the duplicate checks by time see only this run's rows
BASE = 1_500_000_000 + random.randrange(10_000_000)


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _cleanup():
    from app.database import get_db_context
    from app.models import NetfilterLog, PostfixLog, RawServiceLog, RspamdLog
    with get_db_context() as db:
        db.query(PostfixLog).filter(PostfixLog.message.like(f'%{MARK}%')).delete(synchronize_session=False)
        db.query(RspamdLog).filter(RspamdLog.message_id.like(f'%{MARK}%')).delete(synchronize_session=False)
        db.query(NetfilterLog).filter(NetfilterLog.message.like(f'%{MARK}%')).delete(synchronize_session=False)
        db.query(RawServiceLog).filter(
            RawServiceLog.raw_data['message'].astext.like(f'%{MARK}%')).delete(synchronize_session=False)
        db.commit()


@pytest.fixture()
def env(monkeypatch):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import init_db
    init_db()
    _cleanup()
    monkeypatch.setattr(scheduler, 'seen_postfix', set())
    monkeypatch.setattr(scheduler, 'seen_rspamd', set())
    monkeypatch.setattr(scheduler, 'seen_netfilter', set())
    monkeypatch.setattr(scheduler, 'is_blacklisted', lambda email: False)
    yield
    _cleanup()


def _rows(model, column):
    from app.database import get_db_context
    with get_db_context() as db:
        rows = db.query(model).filter(column.like(f'%{MARK}%')).all()
        db.expunge_all()
        return rows


def _forget_the_page(monkeypatch):
    """A later cycle: the in-memory duplicate caches are gone, only the
    stored rows tell that the lines are known."""
    monkeypatch.setattr(scheduler, 'seen_postfix', set())
    monkeypatch.setattr(scheduler, 'seen_rspamd', set())
    monkeypatch.setattr(scheduler, 'seen_netfilter', set())


def test_postfix_page_with_nul_keeps_every_line_and_stores_it_once(env, monkeypatch):
    from app.models import PostfixLog
    logs = [{'time': str(BASE + i), 'program': 'postfix/cleanup', 'priority': 'info',
             'message': f'ABC{i}{MARK[:4].upper()}: message-id=<{i}-{MARK}@example.com>'} for i in range(3)]
    logs.insert(1, {'time': str(BASE + 5), 'program': 'postfix/cleanup', 'priority': 'info',
                    'message': f'ABC5{MARK[:4].upper()}: message-id=<nul\x00-{MARK}@example.com>',
                    'extra\x00key': 'value\x00'})

    new, _, _ = scheduler._store_postfix_page(logs)

    rows = _rows(PostfixLog, PostfixLog.message)
    assert new == 4 and len(rows) == 4
    nul = next(r for r in rows if 'nul' in r.message)
    assert '\x00' not in nul.message and nul.message_id == f'nul-{MARK}@example.com'
    assert nul.raw_data['extrakey'] == 'value'

    _forget_the_page(monkeypatch)
    new, skipped, _ = scheduler._store_postfix_page(logs)
    assert (new, skipped) == (0, 4)
    assert len(_rows(PostfixLog, PostfixLog.message)) == 4


def _rspamd_entry(i, **fields):
    entry = {'unix_time': BASE + i, 'message-id': f'{i}-{MARK}@example.com', 'subject': 'Hello',
             'sender_smtp': 'sender@example.com', 'rcpt_smtp': ['user@example.com'],
             'score': 1.0, 'action': 'no action', 'symbols': {'ARC_NA': {'score': 0}}}
    entry.update(fields)
    return entry


def test_rspamd_page_with_nul_keeps_every_entry_and_stores_it_once(env, monkeypatch):
    from app.models import RspamdLog
    logs = [_rspamd_entry(0),
            _rspamd_entry(1, subject='Invoice\x00 attached'),
            _rspamd_entry(2, **{'message-id': f'2-nul\x00-{MARK}@example.com',
                                'symbols': {'SYM\x00BOL': {'score': 0, 'options': ['a\x00b']}}}),
            _rspamd_entry(3)]

    new, _, _ = scheduler._store_rspamd_page(logs)

    rows = {r.message_id: r for r in _rows(RspamdLog, RspamdLog.message_id)}
    assert new == 4 and len(rows) == 4
    assert rows[f'1-{MARK}@example.com'].subject == 'Invoice attached'
    nul = rows[f'2-nul-{MARK}@example.com']
    assert nul.symbols == {'SYMBOL': {'score': 0, 'options': ['ab']}}
    assert nul.raw_data['message-id'] == f'2-nul-{MARK}@example.com'

    _forget_the_page(monkeypatch)
    new, skipped, _ = scheduler._store_rspamd_page(logs)
    assert (new, skipped) == (0, 4)
    assert len(_rows(RspamdLog, RspamdLog.message_id)) == 4


def test_netfilter_batch_with_nul_keeps_every_line_and_stores_it_once(env, monkeypatch):
    from app.models import NetfilterLog
    logs = [{'time': BASE + i, 'priority': 'warn',
             'message': f'192.0.2.{i + 1} banned {MARK}'} for i in range(3)]
    logs.append({'time': BASE + 9, 'priority': 'warn',
                 'message': f'192.0.2.9 banned \x00{MARK}'})

    scheduler._store_netfilter_logs(logs)
    rows = _rows(NetfilterLog, NetfilterLog.message)
    assert len(rows) == 4
    assert all('\x00' not in r.message for r in rows)

    _forget_the_page(monkeypatch)
    scheduler._store_netfilter_logs(logs)
    assert len(_rows(NetfilterLog, NetfilterLog.message)) == 4


def test_raw_log_page_with_nul_keeps_every_line_and_stores_it_once(env):
    from app.models import RawServiceLog
    service = 'sogo'
    logs = [{'time': str(BASE + i), 'program': service, 'message': f'{MARK} line {i}'} for i in range(3)]
    logs.insert(1, {'time': str(BASE + 7), 'program': service, 'message': f'{MARK} line \x00 7',
                    'key\x00': ['v\x00']})
    # The same line twice, the second time with a NUL that cleaning removes
    logs.append({'time': str(BASE + 0), 'program': service, 'message': f'{MARK} line \x000'})

    async def fetch(method, *args, **kwargs):
        assert method == 'get_raw_logs'
        return list(logs)

    head, deeper, _, _ = asyncio.run(raw_logs_worker._collect_service_in_worker(service, 100, fetch))

    rows = _rows(RawServiceLog, RawServiceLog.raw_data['message'].astext)
    assert len(head) == 4 and deeper == [] and len(rows) == 4
    nul = next(r for r in rows if r.raw_data['message'] == f'{MARK} line  7')
    assert nul.raw_data['key'] == ['v']

    head, _, _, _ = asyncio.run(raw_logs_worker._collect_service_in_worker(service, 100, fetch))
    assert head == []
    assert len(_rows(RawServiceLog, RawServiceLog.raw_data['message'].astext)) == 4


# ---- a row the database still refuses is skipped alone ----

def test_a_refused_rspamd_entry_is_skipped_without_its_page(env):
    from app.models import RspamdLog
    # size is an INTEGER column: PostgreSQL refuses this value for the row alone
    logs = [_rspamd_entry(0), _rspamd_entry(1, size=2 ** 40), _rspamd_entry(2)]

    new, _, _ = scheduler._store_rspamd_page(logs)

    stored = sorted(r.message_id for r in _rows(RspamdLog, RspamdLog.message_id))
    assert stored == [f'0-{MARK}@example.com', f'2-{MARK}@example.com']
    # It was new: paging must not stop as if the page were all duplicates
    assert new == 3


def test_a_refused_entry_does_not_stop_paging_before_the_lines_behind_it(env, monkeypatch):
    from app.models import RspamdLog
    stored_before = [_rspamd_entry(0), _rspamd_entry(1)]
    scheduler._store_rspamd_page(stored_before)
    _forget_the_page(monkeypatch)
    # Newest first: page 1 holds the refused entry beside known ones, page 2 new ones
    pages = stored_before + [_rspamd_entry(2, size=2 ** 40)] + [_rspamd_entry(i) for i in (3, 4, 5)]

    async def page(page_size, offset):
        return pages[offset:offset + page_size]
    monkeypatch.setattr(scheduler, '_discover_total_logs', AsyncMock(return_value=len(pages)))
    monkeypatch.setattr(scheduler.mailcow_api, 'get_rspamd_logs_page', page)
    monkeypatch.setattr(settings._inner, 'fetch_count_rspamd', 3)
    monkeypatch.setattr(settings._inner, 'fetch_max_pages', 5)
    monkeypatch.setitem(scheduler._resume_offset, 'rspamd', 0)

    asyncio.run(scheduler.fetch_and_store_rspamd())

    stored = sorted(r.message_id for r in _rows(RspamdLog, RspamdLog.message_id))
    assert stored == [f'{i}-{MARK}@example.com' for i in (0, 1, 3, 4, 5)]


def test_a_failure_that_is_not_the_rows_own_still_fails_the_page():
    """A lost connection or a broken constraint fails every row alike: the
    page is not committed and is read again next cycle."""
    from sqlalchemy.exc import DataError, IntegrityError, OperationalError
    from app.services.db_values import is_row_error, _is_refused_row

    def orig(pgcode):
        error = Exception('refused')
        error.pgcode = pgcode
        return error
    assert _is_refused_row(DataError('INSERT', {}, orig('22003')))
    assert _is_refused_row(IntegrityError('INSERT', {}, orig('23505')))
    assert not _is_refused_row(IntegrityError('INSERT', {}, orig('23502')))
    assert not _is_refused_row(OperationalError('INSERT', {}, orig('08006')))
    assert not is_row_error(IntegrityError('INSERT', {}, orig('23505')))


def test_a_failure_that_is_not_the_rows_own_is_raised(env):
    from app.database import SessionLocal
    from app.models import QuarantineRuleLog
    from app.services.db_values import add_rows
    from sqlalchemy.exc import IntegrityError
    with SessionLocal() as db:
        with pytest.raises(IntegrityError):
            # rule_id is NOT NULL: a constraint, not a value of this row alone
            add_rows(db, QuarantineRuleLog, [
                dict(rule_id=1, action='release', quarantine_id=MARK),
                dict(rule_id=None, action='release', quarantine_id=MARK),
            ], 'test row')
        db.rollback()
        assert db.query(QuarantineRuleLog).filter(QuarantineRuleLog.quarantine_id == MARK).count() == 0


# ---- quarantine rule history after an action mailcow already did ----

@pytest.fixture()
def quarantine(monkeypatch):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import get_db_context, init_db
    from app.models import QuarantineRule, QuarantineRuleLog
    init_db()
    monkeypatch.setattr(type(settings._inner), 'is_feature_enabled', lambda self, name: True)
    monkeypatch.setattr(settings._inner, 'quarantine_rules_max_actions', 10)
    monkeypatch.setattr(settings._inner, 'quarantine_rules_log_retention_days', 7)
    monkeypatch.setattr(scheduler.mailcow_api, 'headers_rw', {'X-API-Key': 'test-key'})
    monkeypatch.setattr(scheduler.mailcow_api, 'aclose', AsyncMock())
    monkeypatch.setattr(scheduler, 'update_job_status', Mock())
    domain = f'{MARK}.example.com'
    with get_db_context() as db:
        rule = QuarantineRule(name=f'Allow {MARK}', match_type='sender_domain', match_value=domain,
                              is_regex=False, action='release', enabled=True, hit_count=0)
        db.add(rule)
        db.commit()
        rule_id = rule.id

    async def release(ids):
        return [{'type': 'success', 'log': [], 'msg': ['item_released', i]} for i in ids]
    monkeypatch.setattr(scheduler.mailcow_api, 'release_quarantine', AsyncMock(side_effect=release))
    monkeypatch.setattr(scheduler.mailcow_api, 'delete_quarantine', AsyncMock(side_effect=release))
    yield SimpleNamespace(rule_id=rule_id, domain=domain)
    with get_db_context() as db:
        db.query(QuarantineRuleLog).filter(QuarantineRuleLog.rule_id == rule_id).delete()
        db.query(QuarantineRule).filter(QuarantineRule.id == rule_id).delete()
        db.commit()


def test_one_quarantine_item_cannot_cost_the_others_their_history(quarantine, monkeypatch):
    from app.database import get_db_context
    from app.models import QuarantineRule, QuarantineRuleLog
    long_sender = 'a' * 300 + '@' + quarantine.domain
    items = [
        {'id': 101, 'sender': f'one@{quarantine.domain}', 'rcpt': 'rcpt@example.net', 'subject': 'Hello'},
        {'id': 102, 'sender': f'two@{quarantine.domain}', 'rcpt': 'rcpt@example.net', 'subject': 'Hi\x00 there'},
        {'id': 103, 'sender': long_sender, 'rcpt': 'r' * 300 + '@example.net', 'subject': 'Long'},
    ]
    monkeypatch.setattr(scheduler.mailcow_api, 'get_quarantine', AsyncMock(return_value=items))

    asyncio.run(scheduler.process_quarantine_rules_job())

    with get_db_context() as db:
        logs = {row.quarantine_id: row for row in db.query(QuarantineRuleLog).filter(
            QuarantineRuleLog.rule_id == quarantine.rule_id)}
        rule = db.query(QuarantineRule).filter(QuarantineRule.id == quarantine.rule_id).one()
        assert sorted(logs) == ['101', '102', '103']
        assert logs['102'].subject == 'Hi there'
        assert logs['103'].sender == long_sender[:255]
        assert len(logs['103'].recipient) == 255
        assert rule.hit_count == 3
