import asyncio
import re
import uuid

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

MARK = uuid.uuid4().hex[:8]


def format_entry(email, **kwargs):
    from app.routers.suppressions import format_suppression_map_entry
    return format_suppression_map_entry(email, **kwargs)


def _rspamd_match(map_line: str, recipient: str) -> bool:
    m = re.match(r'^/(.*)/(i?)$', map_line)
    body, flags = (m.group(1), m.group(2)) if m else (map_line, '')
    return re.search(body, recipient, re.IGNORECASE if 'i' in flags else 0) is not None


def test_a_bare_address_becomes_an_exact_anchored_pattern():
    line = format_entry('e@example.com')
    assert line == r'/^e@example\.com$/i'
    assert _rspamd_match(line, 'e@example.com')
    assert _rspamd_match(line, 'E@EXAMPLE.COM')
    assert not _rspamd_match(line, 'alice@example.com'), \
        'the reported bug: a superstring recipient must not match'
    assert not _rspamd_match(line, 'joe@example.com')
    assert not _rspamd_match(line, 'e@example.com.evil.net')


def test_regex_metacharacters_in_an_address_are_escaped():
    line = format_entry('a+b.c@example.com')
    assert _rspamd_match(line, 'a+b.c@example.com')
    assert not _rspamd_match(line, 'aab.c@example.com')
    assert not _rspamd_match(line, 'a+bxc@example.com')


def test_a_legacy_domain_pattern_gets_its_anchors():
    line = format_entry(r'/.+@example\.com/i', allow_regex=True)
    assert line == r'/^(?:.+@example\.com)$/i'
    assert _rspamd_match(line, 'user@example.com')
    assert not _rspamd_match(line, 'user@example.com.evil.net')
    assert not _rspamd_match(line, 'user@notexample.com.x')


def test_an_already_anchored_pattern_is_not_anchored_twice():
    line = format_entry(r'/^.+@example\.com$/i', allow_regex=True)
    assert line == r'/^(?:.+@example\.com)$/i'


def test_a_regex_shaped_value_is_a_literal_unless_regex_is_allowed():
    line = format_entry(r'/.+@example\.com/i')
    assert line == r'/^/\.\+@example\\\.com/i$/i'
    assert not _rspamd_match(line, 'user@example.com')


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _cleanup():
    from app.database import get_db_context
    from app.models import SpamSuppression
    with get_db_context() as db:
        db.query(SpamSuppression).filter(
            SpamSuppression.email.like(f'%{MARK}%')).delete(synchronize_session=False)
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


def test_sync_writes_lines_that_do_not_match_superstrings(env, monkeypatch):
    from app.database import get_db_context
    from app.models import SpamSuppression
    from app.routers import suppressions as sup

    email = f'e-{MARK}@example.net'
    innocent = f'alice-{MARK}@example.net'

    written = {}

    async def fake_find(filename):
        return 1

    async def fake_read(map_id):
        return ''

    async def fake_write(filename, content):
        written['content'] = content
        return {'type': 'success'}

    monkeypatch.setattr(sup.mailcow_api, 'find_rspamd_map_id', fake_find)
    monkeypatch.setattr(sup.mailcow_api, 'get_rspamd_map_content', fake_read)
    monkeypatch.setattr(sup.mailcow_api, 'edit_rspamd_map', fake_write)

    with get_db_context() as db:
        db.add(SpamSuppression(email=email, type='email', reason='hard_bounce', source='auto', active=True))
        db.commit()
        asyncio.run(sup.sync_suppressions_to_rspamd(db))

    assert 'content' in written, 'the sync must write the map'
    managed = [l for l in written['content'].split('\n')
               if email.replace('+', '') in l or MARK in l]
    assert managed, 'the suppression must be in the managed section'
    line = managed[0].strip()
    assert _rspamd_match(line, email), 'the suppressed address itself must match'
    assert not _rspamd_match(line, innocent), \
        'an innocent recipient containing the address must not match'


def test_second_sync_with_unchanged_entries_skips_the_write(env, monkeypatch):
    from app.database import get_db_context
    from app.models import SpamSuppression
    from app.routers import suppressions as sup

    email = f'skip-{MARK}@example.net'
    state = {'content': '', 'writes': 0}

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

    with get_db_context() as db:
        db.add(SpamSuppression(email=email, type='email', reason='hard_bounce', source='auto', active=True))
        db.commit()
        asyncio.run(sup.sync_suppressions_to_rspamd(db))
        asyncio.run(sup.sync_suppressions_to_rspamd(db))

    assert state['writes'] == 1, 'identical managed content must not be rewritten'


def test_validation_warns_on_bare_addresses_but_does_not_block():
    from app.routers.rspamd_maps import validate_map_content
    findings = validate_map_content('\n'.join([
        '# a comment',
        'e@example.com',
        r'/^safe@example\.com$/i',
        'plainword',
    ]))
    warnings = [f for f in findings if f.get('severity') == 'warning']
    errors = [f for f in findings if f.get('severity', 'error') == 'error']
    assert len(warnings) == 1 and warnings[0]['content'] == 'e@example.com'
    assert errors == []


def test_validation_still_blocks_a_broken_regex():
    from app.routers.rspamd_maps import validate_map_content
    findings = validate_map_content('/[unclosed/i')
    errors = [f for f in findings if f.get('severity', 'error') == 'error']
    assert len(errors) == 1


def test_manual_bare_entries_are_migrated_by_the_sync(env, monkeypatch):
    from app.database import get_db_context
    from app.models import SpamSuppression
    from app.routers import suppressions as sup

    managed = f'managed-{MARK}@example.net'
    state = {'content': (
        '# my manual notes\n'
        f'manual-{MARK}@example.net\n'
        r'/^already@example\.net$/i'
    ), 'writes': 0}

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

    with get_db_context() as db:
        db.add(SpamSuppression(email=managed, type='email', reason='hard_bounce',
                               source='auto', active=True))
        db.commit()
        asyncio.run(sup.sync_suppressions_to_rspamd(db))
        asyncio.run(sup.sync_suppressions_to_rspamd(db))

    lines = state['content'].split('\n')
    assert '# my manual notes' in lines, 'comments must be preserved'
    assert f'manual-{MARK}@example.net' not in lines, 'the bare manual entry must be gone'
    migrated = sup.format_suppression_map_entry(f'manual-{MARK}@example.net')
    assert migrated in lines, 'the manual entry must be anchored in place'
    assert r'/^already@example\.net$/i' in lines, 'anchored entries stay as they are'
    assert state['writes'] == 1, 'migration happens once; the second sync skips'


def test_migrate_manual_map_line_shapes():
    from app.routers.suppressions import migrate_manual_map_line
    assert migrate_manual_map_line('user@example.com') == r'/^user@example\.com$/i'
    assert migrate_manual_map_line('# comment') == '# comment'
    assert migrate_manual_map_line('') == ''
    assert migrate_manual_map_line(r'/^x@y\.z$/i') == r'/^x@y\.z$/i'
    assert migrate_manual_map_line('badword') == 'badword'


def test_the_bare_address_detector_is_not_a_redos_vector():
    import time
    from app.routers.suppressions import migrate_manual_map_line
    hostile = '!@!.' + '!.' * 5000
    start = time.monotonic()
    assert migrate_manual_map_line(hostile) == hostile
    assert migrate_manual_map_line('a@' + 'b.' * 10000 + 'c') == 'a@' + 'b.' * 10000 + 'c'
    assert time.monotonic() - start < 0.5
    assert migrate_manual_map_line('user@sub.example.com') == r'/^user@sub\.example\.com$/i'
