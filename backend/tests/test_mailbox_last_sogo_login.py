"""The last SOGo login mailcow reports since 2026-11a (last_sogo_login, Unix
seconds, 0 for none). Older mailcow versions do not send the field."""
import importlib.util
import uuid
from pathlib import Path

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from fastapi.testclient import TestClient

from app.scheduler import login_time

DOMAIN = f'sogo-{uuid.uuid4().hex[:8]}.example'
WHEN = 1763500000  # 2025-11-18T21:06:40Z


@pytest.mark.parametrize('value, stored', [
    (WHEN, WHEN), (str(WHEN), WHEN), (f' {WHEN} ', WHEN),
    (0, None), ('0', None), (None, None), ('', None), ('-', None), ('x', None),
    (-5, None), (True, None), (False, None),
    # Past 9999 a date cannot show it; past BIGINT the column cannot hold it
    (253402300800, None), (2 ** 63, None), (str(10 ** 30), None),
])
def test_a_login_time_is_unix_seconds_or_none(value, stored):
    assert login_time(value) == stored


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _cleanup():
    from app.database import get_db_context
    from app.models import MailboxStatistics
    with get_db_context() as session:
        session.query(MailboxStatistics).filter(MailboxStatistics.domain == DOMAIN).delete(synchronize_session=False)
        session.commit()


@pytest.fixture()
def db():
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import get_db_context, init_db
    import app.models  # noqa: F401  (the tables init_db creates)
    init_db()
    _cleanup()
    with get_db_context() as session:
        yield session
    _cleanup()


def _mailbox(name, **fields):
    return {'username': f'{name}@{DOMAIN}', 'domain': DOMAIN, 'active': 1,
            'attributes': {'imap_access': '1'}, 'quota': 1024, **fields}


def _shown():
    from app.main import app
    res = TestClient(app).get('/api/mailbox-stats/all', params={'search': DOMAIN})
    assert res.status_code == 200, res.text
    return {m['username'].split('@')[0]: (m['last_sogo_login'], m['quota']) for m in res.json()['mailboxes']}


def test_the_sync_keeps_the_last_sogo_login_and_the_page_shows_it(db):
    from app.routers import mailbox_stats
    from app.scheduler import _store_mailbox_statistics
    _store_mailbox_statistics([
        _mailbox('webmail', last_sogo_login=WHEN),
        _mailbox('never', last_sogo_login=0),
        _mailbox('old-mailcow'),
        # One odd value does not cost the other mailboxes their sync
        _mailbox('odd', last_sogo_login=2 ** 63, last_imap_login=10 ** 30),
    ])
    mailbox_stats.clear_stats_cache()
    assert _shown() == {'webmail': ('2025-11-18T21:06:40Z', 1024), 'never': (None, 1024),
                        'old-mailcow': (None, 1024), 'odd': (None, 1024)}

    # A later sync that reports none, or no field at all, clears a stored time
    _store_mailbox_statistics([
        _mailbox('webmail', last_sogo_login=0, quota=2048),
        _mailbox('never', last_sogo_login=WHEN),
        _mailbox('old-mailcow'),
        _mailbox('odd', last_sogo_login='x'),
    ])
    mailbox_stats.clear_stats_cache()
    assert _shown() == {'webmail': (None, 2048), 'never': ('2025-11-18T21:06:40Z', 1024),
                        'old-mailcow': (None, 1024), 'odd': (None, 1024)}


def _migration():
    path = next((Path(__file__).resolve().parents[1] / 'alembic' / 'versions').glob('*_mailbox_last_sogo_login.py'))
    spec = importlib.util.spec_from_file_location('mailbox_last_sogo_login', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_upgrade_adds_the_column_empty_for_stored_mailboxes(db):
    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    from sqlalchemy import inspect, text
    from app.database import engine
    from app.scheduler import _store_mailbox_statistics
    _store_mailbox_statistics([_mailbox('before', last_sogo_login=WHEN, last_imap_login=WHEN)])
    db.commit()
    db.close()

    def run(step):
        with engine.begin() as connection:
            with Operations.context(MigrationContext.configure(connection)):
                step()

    try:
        run(_migration().downgrade)
        assert 'last_sogo_login' not in {c['name'] for c in inspect(engine).get_columns('mailbox_statistics')}
    finally:
        run(_migration().upgrade)
        # A second run (the fresh-install start made the column already) changes nothing
        run(_migration().upgrade)
    with engine.connect() as connection:
        row = connection.execute(text('SELECT last_sogo_login, last_imap_login FROM mailbox_statistics '
                                      'WHERE username = :u'), {'u': f'before@{DOMAIN}'}).one()
    assert tuple(row) == (None, WHEN)
