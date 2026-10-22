"""The dashboard figures' trends: one function per figure for the card and the
hourly samples, a gap (no sample, and Unknown on the card) when a source did not
answer, the samples of a feature that is off neither written nor served nor
kept, and a switch-off that races a sample never leaves one behind."""
import asyncio
import importlib.util
import pathlib
import threading
import time
import uuid
from datetime import datetime, timedelta

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app.config import settings
from app.mailcow_api import mailcow_api

MARK = uuid.uuid4().hex[:8]


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


@pytest.fixture()
def db_ready(monkeypatch):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import init_db, get_db_context
    from app.models import MetricSnapshot
    init_db()
    monkeypatch.setattr(settings._inner, 'disabled_features', '')

    def cleanup():
        with get_db_context() as db:
            db.query(MetricSnapshot).delete(synchronize_session=False)
            db.commit()
    cleanup()
    yield
    cleanup()


def _client():
    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app)


def _rows(name=None):
    from app.database import get_db_context
    from app.models import MetricSnapshot
    with get_db_context() as db:
        q = db.query(MetricSnapshot.name, MetricSnapshot.slot, MetricSnapshot.value, MetricSnapshot.of)
        if name:
            q = q.filter(MetricSnapshot.name == name)
        return q.order_by(MetricSnapshot.name, MetricSnapshot.slot).all()


def _fake_sources(monkeypatch, storage='45%', fail2ban=True, blocklists=None):
    from app.services import figures, security_addresses
    async def vmail():
        if storage is Exception:
            raise RuntimeError('mailcow down')
        return {'disk': '/dev/sda1', 'used': '45G', 'total': '100G', 'used_percent': storage} if storage else {}
    async def f2b():
        return {'active_bans': [], 'perm_bans': [], 'whitelist': [], 'blacklist': []} if fail2ban else None
    monkeypatch.setattr(mailcow_api, 'get_status_vmail', vmail)
    monkeypatch.setattr(mailcow_api, 'get_fail2ban', f2b)
    monkeypatch.setattr(security_addresses, 'collect', lambda db, f, now=None, hours=24: [{'list': 'review'}, {'list': 'review'}, {'list': 'banned'}])
    import app.routers.blacklist as blacklist
    monkeypatch.setattr(blacklist, 'blacklist_summary_data', lambda session=None: blocklists or {
        'has_data': True, 'status': 'listed', 'hosts': [{'status': 'listed'}, {'status': 'clean'}, {'status': 'clean'}]})
    return figures


def test_each_figure_says_whether_its_source_answered():
    from app.services import figures
    assert figures.parse_percent('45%') == 45.0 and figures.parse_percent(' 7.5 % ') == 7.5 and figures.parse_percent('n/a') is None
    b = figures.blocklists_figure({'has_data': True, 'status': 'listed', 'hosts': [{'status': 'listed'}, {'status': 'unknown'}]})
    assert (b['value'], b['of'], b['valid']) == (1.0, 2.0, True)
    assert not figures.blocklists_figure({'has_data': False, 'status': 'unknown', 'hosts': [{'status': None}]})['valid']
    assert not figures.blocklists_figure({'has_data': True, 'status': 'error', 'hosts': [{'status': 'error'}]})['valid']
    s = figures.security_figures([{'list': 'review'}, {'list': 'banned'}, {'list': 'quiet'}], True)
    assert (s['security_review']['value'], s['security_banned']['value']) == (1.0, 1.0)
    assert not figures.security_figures([{'list': 'review'}], False)['security_review']['valid']


def test_storage_unknown_when_mailcow_does_not_tell_it(db_ready, monkeypatch):
    _fake_sources(monkeypatch, storage=Exception)
    from app.routers import status
    async def nothing():
        return {"summary": {"running": 0, "stopped": 0, "total": 0}}
    async def info():
        return {"domains": {"total": 0}, "mailboxes": {"total": 0}, "aliases": {"total": 0}}
    monkeypatch.setattr(status, '_get_containers_status_internal', nothing)
    monkeypatch.setattr(status, 'get_mailcow_info', info)
    summary = asyncio.run(status.get_status_summary())
    assert summary['storage']['known'] is False
    _fake_sources(monkeypatch, storage='45%')
    assert asyncio.run(status.get_status_summary())['storage'] == {'used_percent': '45%', 'used': '45G', 'total': '100G', 'known': True}


def test_a_run_samples_what_answered_and_leaves_a_gap_for_what_did_not(db_ready, monkeypatch):
    figures = _fake_sources(monkeypatch, storage=Exception, fail2ban=False)
    written = asyncio.run(figures.run_trend_samples())
    names = {r.name for r in _rows()}
    assert names == {'linking_rate', 'blocklists_listed'} and written == 2, names
    blocklists = _rows('blocklists_listed')[0]
    assert (blocklists.value, blocklists.of) == (1.0, 3.0)
    # Everything answers: one sample each in this hour; a second run in the same hour replaces it
    _fake_sources(monkeypatch)
    asyncio.run(figures.run_trend_samples())
    asyncio.run(figures.run_trend_samples())
    rows = _rows()
    assert sorted(r.name for r in rows) == sorted(figures.METRICS), rows
    assert _rows('storage_used')[0].value == 45.0
    assert (_rows('security_review')[0].value, _rows('security_banned')[0].value) == (2.0, 1.0)


def test_a_feature_that_is_off_is_neither_sampled_nor_served_and_its_samples_go(db_ready, monkeypatch):
    figures = _fake_sources(monkeypatch)
    asyncio.run(figures.run_trend_samples())
    monkeypatch.setattr(settings._inner, 'disabled_features', 'netfilter')
    c = _client()
    answer = c.get('/api/stats/trends', params={'names': 'storage_used,security_review', 'days': 7}).json()
    assert set(answer['trends']) == {'storage_used'}
    from app.database import get_db_context
    from app.services.feature_data import purge_feature
    with get_db_context() as db:
        deleted = purge_feature(db, 'netfilter')
    assert deleted.get('metric_snapshots') == 2
    assert not _rows('security_review') and _rows('storage_used')
    asyncio.run(figures.run_trend_samples())
    assert not _rows('security_banned'), 'not sampled while off'


def test_a_switch_off_during_a_run_leaves_no_sample_behind(db_ready, monkeypatch):
    """The run has read its figures; the switch and the delete come; then it writes."""
    figures = _fake_sources(monkeypatch)
    epochs = {f: figures.feature_epoch(f) for f in set(figures.METRICS.values()) if f}
    points = asyncio.run(figures.collect_figures())
    from app.database import get_db_context
    from app.services.feature_data import purge_feature
    monkeypatch.setattr(settings._inner, 'disabled_features', 'netfilter')
    with get_db_context() as db:
        purge_feature(db, 'netfilter')
    figures.write_points(points, epochs, figures.slot_of(datetime.utcnow()))
    assert not _rows('security_review') and _rows('storage_used')
    # Off and on again before the write: that run's samples of it are dropped too
    monkeypatch.setattr(settings._inner, 'disabled_features', '')
    figures.write_points(points, epochs, figures.slot_of(datetime.utcnow()))
    assert not _rows('security_review')


def test_a_write_waits_for_a_purge_in_progress_and_then_writes_nothing_of_it(db_ready, monkeypatch):
    """The purge holds the lock; the write waits, then sees the feature off."""
    figures = _fake_sources(monkeypatch)
    epochs = {f: figures.feature_epoch(f) for f in set(figures.METRICS.values()) if f}
    points = asyncio.run(figures.collect_figures())
    from app.database import get_db_context
    with get_db_context() as db:
        figures.purge_feature_metrics(db, 'netfilter')   # the lock is held until commit
        done = threading.Event()
        worker = threading.Thread(target=lambda: (figures.write_points(points, epochs, figures.slot_of(datetime.utcnow())), done.set()))
        worker.start()
        time.sleep(0.5)
        assert not done.is_set(), 'the write waits for the purge'
        monkeypatch.setattr(settings._inner, 'disabled_features', 'netfilter')
        db.commit()
    worker.join(10)
    assert done.is_set()
    assert not _rows('security_review') and not _rows('security_banned') and _rows('storage_used')


def test_samples_older_than_kept_go_and_the_api_refuses_what_it_does_not_know(db_ready, monkeypatch):
    from app.database import get_db_context
    from app.models import MetricSnapshot
    figures = _fake_sources(monkeypatch)
    with get_db_context() as db:
        old = datetime.utcnow() - timedelta(days=figures.KEEP_DAYS + 2)
        db.add(MetricSnapshot(name='storage_used', slot=old.replace(minute=0, second=0, microsecond=0), value=1.0, as_of=old))
        db.commit()
    asyncio.run(figures.run_trend_samples())
    assert len(_rows('storage_used')) == 1, 'the old sample went'
    c = _client()
    assert c.get('/api/stats/trends', params={'names': 'nope'}).status_code == 422
    assert c.get('/api/stats/trends', params={'names': ','.join(['storage_used'] * 3 + [f'x{i}' for i in range(10)])}).status_code == 422
    assert c.get('/api/stats/trends', params={'names': 'storage_used', 'days': 0}).status_code == 422
    assert c.get('/api/stats/trends', params={'names': 'storage_used', 'days': 91}).status_code == 422
    answer = c.get('/api/stats/trends', params={'names': 'storage_used,storage_used', 'days': 7}).json()
    assert list(answer['trends']) == ['storage_used'] and answer['trends']['storage_used'][0]['value'] == 45.0


def test_the_migration_creates_the_table_on_an_existing_install_and_runs_again_safely(db_ready):
    from sqlalchemy import create_engine, inspect, text
    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    from app.database import engine
    path = sorted((pathlib.Path(__file__).resolve().parent.parent / 'alembic' / 'versions').glob('0021_*.py'))[0]
    spec = importlib.util.spec_from_file_location('rev0021', path)
    revision = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(revision)
    schema = 'trends_' + MARK
    with engine.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA {schema}'))
    isolated = create_engine(engine.url, connect_args={'options': f'-csearch_path={schema}'})

    def run(step):
        with isolated.begin() as conn:
            with Operations.context(MigrationContext.configure(conn)):
                step()
    try:
        run(revision.upgrade)
        run(revision.upgrade)
        assert 'metric_snapshots' in inspect(isolated).get_table_names()
        with isolated.begin() as conn:
            conn.execute(text("INSERT INTO metric_snapshots (name, slot, value, as_of) VALUES ('storage_used', '2026-10-22 10:00', 5, now())"))
            with pytest.raises(Exception):
                with conn.begin_nested():
                    conn.execute(text("INSERT INTO metric_snapshots (name, slot, value, as_of) VALUES ('storage_used', '2026-10-22 10:00', 6, now())"))
        run(revision.downgrade)
        assert 'metric_snapshots' not in inspect(isolated).get_table_names()
    finally:
        isolated.dispose()
        with engine.begin() as conn:
            conn.execute(text(f'DROP SCHEMA {schema} CASCADE'))


def test_an_error_answer_from_fail2ban_is_no_answer(db_ready, monkeypatch):
    from app.services.security_addresses import fail2ban_answered
    assert fail2ban_answered({'active_bans': [], 'ban_time': 600})
    assert not fail2ban_answered({'type': 'danger', 'msg': 'unavailable'})
    assert not fail2ban_answered(None) and not fail2ban_answered([])
    figures = _fake_sources(monkeypatch)
    async def danger():
        return {'type': 'danger', 'msg': 'unavailable'}
    monkeypatch.setattr(mailcow_api, 'get_fail2ban', danger)
    asyncio.run(figures.run_trend_samples())
    assert not _rows('security_review') and not _rows('security_banned') and _rows('storage_used')


def test_a_quick_off_and_on_through_settings_drops_a_running_sample(db_ready, monkeypatch):
    """Off and on again before any purge: the switch itself moves the epoch."""
    figures = _fake_sources(monkeypatch)
    epochs = {f: figures.feature_epoch(f) for f in set(figures.METRICS.values()) if f}
    points = asyncio.run(figures.collect_figures())
    figures.note_feature_switches(set(), {'netfilter'})
    figures.note_feature_switches({'netfilter'}, set())
    figures.write_points(points, epochs, figures.slot_of(datetime.utcnow()))
    assert not _rows('security_review') and _rows('storage_used')


def test_a_sources_queries_stop_together_at_its_time_budget(db_ready):
    """The budget is the source's, not each query's: two queries that each fit
    but together do not are stopped in the second."""
    from sqlalchemy import text
    from app.services import figures
    done = []

    def two(db):
        db.execute(text('SELECT pg_sleep(0.8)'))
        done.append('first')
        db.execute(text('SELECT pg_sleep(0.8)'))
        done.append('second')
    started = time.monotonic()
    with pytest.raises(Exception, match='statement timeout|canceling statement|took more than'):
        figures._in_session(two, budget=1.2)
    assert done == ['first'] and time.monotonic() - started < 1.8
    # Each query is told what is left
    seen = figures._in_session(lambda db: db.execute(text('SHOW statement_timeout')).scalar(), budget=20)
    assert seen.endswith('ms') and 19000 <= int(seen[:-2]) <= 20000


def test_the_blocklist_figure_reads_in_the_bounded_session(db_ready):
    """In the collector's session its query errors are the source's failure, not an empty list."""
    from app.routers.blacklist import blacklist_summary_data

    class Broken:
        def query(self, *a, **k):
            raise RuntimeError('canceling statement due to statement timeout')
    with pytest.raises(RuntimeError):
        blacklist_summary_data(Broken())


def test_a_save_of_the_feature_list_that_cannot_have_the_samples_lock_changes_nothing(db_ready, monkeypatch):
    """The lock is had before anything is saved: busy, the save is refused and nothing changed."""
    from fastapi import HTTPException
    from sqlalchemy import text
    from app.database import engine
    from app.routers import settings as settings_router
    from app.services import figures
    monkeypatch.setattr(settings._inner, 'edit_settings_via_ui_enabled', True)
    monkeypatch.setattr(figures, 'SWITCH_WAIT', '300ms')
    saved = []
    monkeypatch.setattr(settings_router, 'save_config_overrides_to_db', lambda db, values: saved.append(values))
    monkeypatch.setattr(settings_router, 'reload_settings', lambda db: None)
    epochs = {f: figures.feature_epoch(f) for f in set(figures.METRICS.values()) if f}
    holder = engine.connect()
    try:
        holder.execute(text('SELECT pg_advisory_lock(:key)'), {'key': figures._LOCK_KEY})
        holder.commit()
        with pytest.raises(HTTPException) as refused:
            settings_router.update_settings({'disabled_features': 'netfilter'}, db=object())
        assert refused.value.status_code == 503 and 'Nothing was changed' in refused.value.detail
        assert saved == [] and epochs == {f: figures.feature_epoch(f) for f in epochs}
    finally:
        holder.execute(text('SELECT pg_advisory_unlock(:key)'), {'key': figures._LOCK_KEY})
        holder.commit()
        holder.close()
    # Free again: the guard leaves no lock and no timeout behind on the pool
    with figures.feature_switch_guard() as note:
        note()
    with engine.connect() as conn:
        assert conn.execute(text('SELECT pg_try_advisory_lock(:key)'), {'key': figures._LOCK_KEY}).scalar()
        conn.execute(text('SELECT pg_advisory_unlock(:key)'), {'key': figures._LOCK_KEY})
        assert conn.execute(text('SHOW lock_timeout')).scalar() == '0'
        conn.commit()
