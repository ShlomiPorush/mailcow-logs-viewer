"""Automatic suppressions are always written to Rspamd as exact addresses.

global_rcpt_blacklist.map is a regexp map, and the formatter trusted any
stored value shaped /body/flags as a regex. The bounce scan and the
deferred-queue cleanup store recipients taken from Postfix logs and the mail
queue, so a recipient such as /.*|x@y.test/i became a map line matching every
recipient on the server. Only entries an administrator added may be regex.
"""
import asyncio
import re
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, Mock

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

MARK = uuid.uuid4().hex[:8]
EVERYONE = f'/.*|x{MARK}@y.test/i'
WHOLE_DOMAIN = f'/.*@partner{MARK}.test/i'


def _rspamd_match(map_line: str, recipient: str) -> bool:
    """Rspamd's regexp multimap: an unanchored search of the slash-delimited body."""
    m = re.match(r'^/(.*)/(i?)$', map_line)
    body, flags = (m.group(1), m.group(2)) if m else (map_line, '')
    return re.search(body, recipient, re.IGNORECASE if 'i' in flags else 0) is not None


# ---- formatter ----

def test_trusted_regex_is_anchored_as_a_whole():
    """^ and $ must hold across alternation: ^(?:a|b)$, not ^a|b$."""
    from app.routers.suppressions import format_suppression_map_entry
    line = format_suppression_map_entry(r'/a@example\.com|b@example\.com/i', allow_regex=True)
    assert _rspamd_match(line, 'a@example.com')
    assert _rspamd_match(line, 'b@example.com')
    assert not _rspamd_match(line, 'evil-b@example.com')
    assert not _rspamd_match(line, 'a@example.com.evil.test')


def test_untrusted_regex_shape_is_written_as_a_literal():
    from app.routers.suppressions import format_suppression_map_entry
    line = format_suppression_map_entry(EVERYONE, allow_regex=False)
    assert _rspamd_match(line, EVERYONE)
    assert not _rspamd_match(line, 'someone@unrelated.example.com')


# ---- the sync, through the real database ----

def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _cleanup():
    from app.database import get_db_context
    from app.models import PostfixLog, SpamSuppression
    with get_db_context() as db:
        db.query(SpamSuppression).filter(
            SpamSuppression.email.like(f'%{MARK}%')).delete(synchronize_session=False)
        db.query(PostfixLog).filter(PostfixLog.message.like(f'%{MARK}%')).delete(synchronize_session=False)
        db.commit()


@pytest.fixture()
def env():
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import init_db
    init_db()
    _cleanup()
    yield
    _cleanup()


def _fake_map(monkeypatch, initial=''):
    from app.routers import suppressions as sup
    state = {'content': initial, 'writes': 0}

    async def fake_find(filename):
        return 1

    async def fake_read(map_id):
        return state['content']

    async def fake_write(filename, content):
        state['content'] = content
        state['writes'] += 1
        return {'type': 'success'}

    monkeypatch.setattr(sup.mailcow_api, 'find_rspamd_map_id', fake_find)
    monkeypatch.setattr(sup.mailcow_api, 'get_rspamd_map_content', fake_read)
    monkeypatch.setattr(sup.mailcow_api, 'edit_rspamd_map', fake_write)
    return state


def _managed_lines(content):
    from app.routers.suppressions import MANAGED_MARKER_START, MANAGED_MARKER_END
    lines, inside = [], False
    for line in content.split('\n'):
        if MANAGED_MARKER_START in line:
            inside = True
            continue
        if MANAGED_MARKER_END in line:
            break
        if inside and line.strip() and not line.startswith('#'):
            lines.append(line.strip())
    return lines


def test_auto_row_shaped_like_a_regex_never_reaches_rspamd_as_one(env, monkeypatch):
    from app.database import get_db_context
    from app.models import SpamSuppression
    from app.routers import suppressions as sup

    state = _fake_map(monkeypatch)
    with get_db_context() as db:
        for email in (EVERYONE, WHOLE_DOMAIN):
            db.add(SpamSuppression(email=email, type='email', reason='hard_bounce', source='auto', active=True))
        db.commit()
        asyncio.run(sup.sync_suppressions_to_rspamd(db))

    lines = [l for l in _managed_lines(state['content']) if MARK in l]
    assert len(lines) == 2
    for line in lines:
        assert not _rspamd_match(line, 'someone@unrelated.example.com')
        assert not _rspamd_match(line, f'ceo@partner{MARK}.test')


def test_existing_auto_regex_line_is_rewritten_on_the_next_sync(env, monkeypatch):
    """Upgrade path: a map already holding the dangerous line written by the
    old code is corrected by the next sync, with no operator action."""
    from app.database import get_db_context
    from app.models import SpamSuppression
    from app.routers import suppressions as sup

    old_line = f'/^.*@partner{MARK}.test$/i'
    initial = '\n'.join([
        '/^manual@example\\.com$/i',
        '',
        sup.MANAGED_MARKER_START,
        '# Last sync: 2026-01-01T00:00:00Z | Active: 1',
        old_line,
        sup.MANAGED_MARKER_END,
    ])
    state = _fake_map(monkeypatch, initial)
    with get_db_context() as db:
        db.add(SpamSuppression(email=WHOLE_DOMAIN, type='email', reason='hard_bounce', source='auto',
                               active=True, synced_to_rspamd=True))
        db.commit()
        asyncio.run(sup.sync_suppressions_to_rspamd(db))

    assert state['writes'] == 1, 'the dangerous managed line must be rewritten'
    assert old_line not in state['content']
    assert '/^manual@example\\.com$/i' in state['content'], 'manual entries are kept'
    line = [l for l in _managed_lines(state['content']) if MARK in l][0]
    assert not _rspamd_match(line, f'ceo@partner{MARK}.test')


def test_manual_domain_regex_still_works(env, monkeypatch):
    from app.database import get_db_context
    from app.models import SpamSuppression
    from app.routers import suppressions as sup

    state = _fake_map(monkeypatch)
    domain = f'manual{MARK}.example.com'
    with get_db_context() as db:
        db.add(SpamSuppression(email=f'/^.+@{re.escape(domain)}$/i', type='domain', reason='manual',
                               source='manual', active=True))
        db.commit()
        asyncio.run(sup.sync_suppressions_to_rspamd(db))

    line = [l for l in _managed_lines(state['content']) if MARK in l][0]
    assert _rspamd_match(line, f'anyone@{domain}')
    assert not _rspamd_match(line, f'anyone@{domain}.evil.test')


# ---- the auto paths refuse such recipients ----

def test_bounce_scan_does_not_suppress_a_recipient_with_a_slash_in_the_domain(env, monkeypatch):
    from app import scheduler
    from app.config import settings
    from app.database import get_db_context
    from app.models import PostfixLog, SpamSuppression

    with get_db_context() as db:
        for i, rcpt in enumerate((EVERYONE, f'real{MARK}@example.net')):
            db.add(PostfixLog(time=datetime.utcnow(), created_at=datetime.utcnow(), program='postfix/smtp',
                              priority='info', message=f'bounce {MARK} {i}', queue_id=f'ABC{MARK[:4].upper()}{i}',
                              recipient=rcpt, status='bounced', dsn='5.4.4'))
        db.commit()
    monkeypatch.setattr(settings._inner, 'suppression_whitelist_domains', '')
    scheduler._detect_suppressions_worker()

    with get_db_context() as db:
        emails = {s.email for s in db.query(SpamSuppression).filter(
            SpamSuppression.email.like(f'%{MARK}%')).all()}
    assert emails == {f'real{MARK}@example.net'}


def test_deferred_cleanup_does_not_suppress_a_recipient_with_a_slash_in_the_domain(monkeypatch):
    from app import scheduler
    from app.config import settings

    monkeypatch.setattr(type(settings._inner), 'is_feature_enabled', lambda self, name: True)
    for key, value in {'suppression_enabled': True, 'queue_cleanup_enabled': True,
                       'queue_cleanup_threshold_minutes': 30, 'suppression_rspamd_sync': False,
                       'suppression_whitelist_domains': ''}.items():
        monkeypatch.setattr(settings._inner, key, value)
    monkeypatch.setattr(scheduler.mailcow_api, 'headers_rw', {'X-API-Key': 'test-key'})
    monkeypatch.setattr(scheduler, 'update_job_status', Mock())
    old = datetime.now(timezone.utc).timestamp() - 7200
    monkeypatch.setattr(scheduler.mailcow_api, 'get_queue', AsyncMock(return_value=[
        {'queue_id': 'OLD', 'queue_name': 'deferred', 'arrival_time': old,
         'recipients': [EVERYONE, 'stuck@example.net']}]))
    monkeypatch.setattr(scheduler.mailcow_api, 'delete_queue', AsyncMock())
    captured = []
    monkeypatch.setattr(scheduler, '_store_deferred_suppressions_worker',
                        lambda recipients: captured.extend(recipients) or len(recipients))

    asyncio.run(scheduler.cleanup_deferred_queue_job())
    assert captured == ['stuck@example.net']
