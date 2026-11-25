import importlib.util
import uuid
from pathlib import Path

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from fastapi.testclient import TestClient

from app.scheduler import login_time

DOMAIN = f'sogo-{uuid.uuid4().hex[:8]}.test'
WHEN = 1763500000


@pytest.mark.parametrize('value, stored', [
    (WHEN, WHEN), (str(WHEN), WHEN), (f' {WHEN} ', WHEN),
    (0, None), ('0', None), (None, None), ('', None), ('-', None), ('x', None),
    (-5, None), (True, None), (False, None), (WHEN + 0.5, None), (f'{WHEN}.5', None),
    (253402300800, None), (2 ** 63, None), (str(10 ** 30), None),
])
def test_a_login_time_is_unix_seconds_or_none(value, stored):
    assert login_time(value) == stored


@pytest.fixture()
def db(app_schema):
    from app.database import get_db_context
    from app.models import MailboxStatistics
    with get_db_context() as session:
        others = session.query(MailboxStatistics.id, MailboxStatistics.active, MailboxStatistics.updated_at).all()
    yield
    with get_db_context() as session:
        session.query(MailboxStatistics).filter(MailboxStatistics.domain == DOMAIN).delete(synchronize_session=False)
        for row_id, active, updated_at in others:
            session.query(MailboxStatistics).filter(MailboxStatistics.id == row_id).update(
                {MailboxStatistics.active: active, MailboxStatistics.updated_at: updated_at}, synchronize_session=False)


def _mailbox(name, **fields):
    return {'username': f'{name}@{DOMAIN}', 'domain': DOMAIN, 'active': 1,
            'attributes': {'imap_access': '1'}, 'quota': 1024, **fields}


def _shown():
    from app.main import app
    res = TestClient(app).get('/api/mailbox-stats/all', params={'search': DOMAIN})
    assert res.status_code == 200, res.text
    return {m['username'].split('@')[0]: (m['last_sogo_login'], m['quota']) for m in res.json()['mailboxes']}


def test_the_sync_keeps_the_last_sogo_login_and_the_page_shows_it(db):
    from app.scheduler import _store_mailbox_statistics
    _store_mailbox_statistics([
        _mailbox('webmail', last_sogo_login=WHEN),
        _mailbox('downgraded', last_sogo_login=WHEN),
        _mailbox('never', last_sogo_login=0),
        _mailbox('old-mailcow'),
        _mailbox('odd', last_sogo_login=2 ** 63, last_imap_login=10 ** 30),
    ])
    assert _shown() == {'webmail': ('2025-11-18T21:06:40Z', 1024), 'downgraded': ('2025-11-18T21:06:40Z', 1024),
                        'never': (None, 1024), 'old-mailcow': (None, 1024), 'odd': (None, 1024)}

    _store_mailbox_statistics([
        _mailbox('webmail', last_sogo_login=0, quota=2048),
        _mailbox('downgraded'),
        _mailbox('never', last_sogo_login=WHEN),
        _mailbox('old-mailcow'),
        _mailbox('odd', last_sogo_login='x'),
    ])
    assert _shown() == {'webmail': (None, 2048), 'downgraded': (None, 1024), 'never': ('2025-11-18T21:06:40Z', 1024),
                        'old-mailcow': (None, 1024), 'odd': (None, 1024)}


def _migration():
    path = next((Path(__file__).resolve().parents[1] / 'alembic' / 'versions').glob('*_mailbox_last_sogo_login.py'))
    spec = importlib.util.spec_from_file_location('mailbox_last_sogo_login', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_upgrade_adds_the_column_empty_for_stored_mailboxes(app_schema):
    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    from sqlalchemy import create_engine, inspect, text
    from app.database import engine
    from app.models import Base, MailboxStatistics
    schema = 'sogo_login_' + uuid.uuid4().hex[:8]
    with engine.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA {schema}'))
    isolated = create_engine(engine.url, connect_args={'options': f'-csearch_path={schema}'})

    def run(step):
        with isolated.begin() as conn:
            with Operations.context(MigrationContext.configure(conn)):
                step()

    def stored():
        with isolated.connect() as conn:
            return conn.execute(text('SELECT username, last_imap_login FROM mailbox_statistics')).all()

    try:
        Base.metadata.create_all(isolated, tables=[MailboxStatistics.__table__])
        with isolated.begin() as conn:
            conn.execute(text('ALTER TABLE mailbox_statistics DROP COLUMN last_sogo_login'))
            conn.execute(text("INSERT INTO mailbox_statistics (username, domain, last_imap_login) "
                              f"VALUES ('before@{DOMAIN}', '{DOMAIN}', {WHEN})"))
        run(_migration().upgrade)
        run(_migration().upgrade)
        with isolated.connect() as conn:
            assert conn.execute(text('SELECT last_sogo_login FROM mailbox_statistics')).all() == [(None,)]
        assert stored() == [(f'before@{DOMAIN}', WHEN)]
        run(_migration().downgrade)
        assert 'last_sogo_login' not in {c['name'] for c in inspect(isolated).get_columns('mailbox_statistics')}
        assert stored() == [(f'before@{DOMAIN}', WHEN)]
    finally:
        isolated.dispose()
        with engine.begin() as conn:
            conn.execute(text(f'DROP SCHEMA {schema} CASCADE'))
