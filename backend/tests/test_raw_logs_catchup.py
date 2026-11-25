import asyncio
import uuid

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app.config import settings

MARKER = uuid.uuid4().hex[:8]


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


class FakeMailcow:
    INDEX_BASE = {'rspamd-history': 0}

    def __init__(self):
        self.lists = {}
        self.calls = []

    def seed(self, service, n, start_time=1_800_000_000):
        self.lists[service] = [
            {'time': str(start_time - i), 'program': service,
             'message': f'{MARKER} {service} line {n - i}'}
            for i in range(n)
        ]

    def push_newer(self, service, n):
        newest = int(self.lists[service][0]['time']) if self.lists[service] else 1_800_000_000
        fresh = [
            {'time': str(newest + n - i), 'program': service,
             'message': f'{MARKER} {service} newer {uuid.uuid4().hex[:6]} {i}'}
            for i in range(n)
        ]
        self.lists[service] = fresh + self.lists[service]

    async def get_raw_logs(self, service, count=1000):
        self.calls.append((service, 'head', count))
        return list(self.lists.get(service, [])[:count])

    async def get_raw_logs_range(self, service, offset, page_size):
        self.calls.append((service, 'range', offset))
        base = self.INDEX_BASE.get(service, 1)
        first = offset - base
        return list(self.lists.get(service, [])[first:first + page_size])

    def range_calls(self, service):
        return [c for c in self.calls if c[0] == service and c[1] == 'range']


def _cleanup():
    from app.database import get_db_context
    from app.models import RawServiceLog, SystemSetting
    with get_db_context() as db:
        db.query(RawServiceLog).filter(
            RawServiceLog.raw_data['message'].astext.like(f'{MARKER}%')
        ).delete(synchronize_session=False)
        db.query(SystemSetting).filter(
            SystemSetting.key.like('raw_logs_catchup:%')
        ).delete(synchronize_session=False)
        db.commit()


def _stored(service):
    from app.database import get_db_context
    from app.models import RawServiceLog
    with get_db_context() as db:
        return db.query(RawServiceLog).filter(
            RawServiceLog.service == service,
            RawServiceLog.raw_data['message'].astext.like(f'{MARKER}%'),
        ).count()


@pytest.fixture()
def env(monkeypatch):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import init_db
    from app import raw_logs_worker as worker
    init_db()
    fake = FakeMailcow()
    monkeypatch.setattr(worker, 'mailcow_api', fake)
    monkeypatch.setattr(worker, '_ws_broadcast_fn', None)
    monkeypatch.setattr(worker, '_ws_broadcast_all_fn', None)
    monkeypatch.setattr(settings._inner, 'raw_logs_fetch_count', 100)
    monkeypatch.setattr(settings._inner, 'fetch_count_rspamd', 50)
    getattr(worker, '_catchup_state', {}).clear()

    def cycle(services):
        monkeypatch.setattr(settings._inner, 'raw_logs_services', ','.join(services))
        monkeypatch.setattr(type(settings._inner), 'raw_logs_required', property(lambda self: {}))
        asyncio.run(worker.fetch_raw_service_logs())
    fake.cycle = cycle

    _cleanup()
    yield fake
    _cleanup()
    getattr(worker, '_catchup_state', {}).clear()


def test_quiet_cycle_makes_one_request_per_service(env):
    env.seed('postfix', 300)
    env.cycle(['postfix'])
    env.calls.clear()
    env.push_newer('postfix', 10)
    env.cycle(['postfix'])
    assert env.calls == [('postfix', 'head', 100)]
    assert _stored('postfix') == 310


def test_burst_larger_than_one_page_is_collected_in_full(env):
    env.seed('postfix', 100)
    env.cycle(['postfix'])
    assert _stored('postfix') == 100
    env.push_newer('postfix', 250)
    env.cycle(['postfix'])
    assert _stored('postfix') == 350, 'lines beyond the first page were lost'


def test_first_start_imports_the_whole_list_across_cycles(env, monkeypatch):
    from app import raw_logs_worker as worker
    monkeypatch.setattr(worker, 'CATCHUP_MAX_PAGES_PER_CYCLE', 2)
    env.seed('postfix', 750)
    env.cycle(['postfix'])
    first = _stored('postfix')
    assert 100 < first < 750, 'one cycle must neither stop at the head nor do it all'
    assert 'postfix' in worker._catchup_state, 'the walk must be marked pending'
    for _ in range(10):
        if 'postfix' not in worker._catchup_state:
            break
        env.cycle(['postfix'])
    assert _stored('postfix') == 750
    assert 'postfix' not in worker._catchup_state


def test_one_based_range_overlap_never_duplicates_or_skips(env):
    env.seed('postfix', 230)
    env.cycle(['postfix'])
    assert _stored('postfix') == 230


def test_zero_based_rspamd_history_never_skips_a_line(env):
    env.seed('rspamd-history', 120)
    env.cycle(['rspamd-history'])
    assert _stored('rspamd-history') == 120


def test_walk_stops_when_it_meets_previously_imported_history(env):
    env.seed('postfix', 400)
    env.cycle(['postfix'])
    env.calls.clear()
    env.push_newer('postfix', 180)
    env.cycle(['postfix'])
    assert _stored('postfix') == 580
    assert len(env.range_calls('postfix')) <= 3


def test_services_outside_the_catchup_set_never_page_deeper(env):
    env.seed('dovecot', 300)
    env.cycle(['dovecot'])
    assert env.range_calls('dovecot') == []
    assert _stored('dovecot') == 100


def test_a_partial_head_page_is_not_treated_as_a_gap(env):
    env.seed('postfix', 40)
    env.cycle(['postfix'])
    assert env.range_calls('postfix') == []
    assert _stored('postfix') == 40


def _drain(env, worker, max_cycles=40):
    for _ in range(max_cycles):
        if 'postfix' not in worker._catchup_state:
            return
        env.cycle(['postfix'])
    raise AssertionError('walk never finished')


def test_burst_of_a_full_page_while_a_walk_is_pending_loses_nothing(env, monkeypatch):
    from app import raw_logs_worker as worker
    monkeypatch.setattr(worker, 'CATCHUP_MAX_PAGES_PER_CYCLE', 2)
    env.seed('postfix', 750)
    env.cycle(['postfix'])
    assert 'postfix' in worker._catchup_state
    env.push_newer('postfix', 150)
    env.cycle(['postfix'])
    _drain(env, worker)
    assert _stored('postfix') == 900


def test_burst_larger_than_a_cycle_budget_while_pending_still_completes(env, monkeypatch):
    from app import raw_logs_worker as worker
    monkeypatch.setattr(worker, 'CATCHUP_MAX_PAGES_PER_CYCLE', 2)
    env.seed('postfix', 600)
    env.cycle(['postfix'])
    env.push_newer('postfix', 450)
    env.cycle(['postfix'])
    _drain(env, worker)
    assert _stored('postfix') == 1050


def test_a_failed_commit_keeps_the_resume_position(env, monkeypatch):
    from app import raw_logs_worker as worker
    from app import database
    monkeypatch.setattr(worker, 'CATCHUP_MAX_PAGES_PER_CYCLE', 2)
    env.seed('postfix', 750)
    env.cycle(['postfix'])
    before = dict(worker._catchup_state['postfix'])

    real_ctx = database.get_db_context
    class Boom(Exception):
        pass
    from contextlib import contextmanager

    @contextmanager
    def failing_ctx():
        with real_ctx() as db:
            real_commit = db.commit
            def commit():
                raise Boom('simulated commit failure')
            db.commit = commit
            try:
                yield db
            finally:
                db.commit = real_commit
    monkeypatch.setattr(worker, 'get_db_context', failing_ctx)
    env.cycle(['postfix'])
    assert worker._catchup_state['postfix'] == before, 'resume position moved despite rollback'

    monkeypatch.setattr(worker, 'get_db_context', real_ctx)
    _drain(env, worker)
    assert _stored('postfix') == 750


def test_a_failing_range_request_keeps_the_head_page(env, monkeypatch):
    from app import raw_logs_worker as worker
    from app.mailcow_api import MailcowAPIError
    monkeypatch.setattr(worker, 'CATCHUP_MAX_PAGES_PER_CYCLE', 3)
    env.seed('postfix', 500)
    real_range = env.get_raw_logs_range
    calls = {'n': 0}

    async def flaky(service, offset, page_size):
        calls['n'] += 1
        if calls['n'] == 2:
            raise MailcowAPIError('simulated 5xx')
        return await real_range(service, offset, page_size)
    monkeypatch.setattr(env, 'get_raw_logs_range', flaky)

    env.cycle(['postfix'])
    assert _stored('postfix') >= 100, 'head page was discarded'
    assert 'postfix' in worker._catchup_state, 'walk must remain pending after the failure'
    _drain(env, worker)
    assert _stored('postfix') == 500


def test_only_head_page_lines_are_streamed_to_the_live_page(env, monkeypatch):
    from app import raw_logs_worker as worker
    sent = []

    async def capture(service, entries):
        sent.append((service, list(entries)))
    monkeypatch.setattr(worker, '_ws_broadcast_fn', capture)

    env.seed('postfix', 100)
    env.cycle(['postfix'])
    sent.clear()
    env.push_newer('postfix', 250)
    env.cycle(['postfix'])
    assert _stored('postfix') == 350
    assert len(sent) == 1
    service, entries = sent[0]
    assert len(entries) == 100, 'only the head page may be streamed live'
    assert all('newer' in e['message'] for e in entries)


def test_a_pending_walk_survives_a_restart(env, monkeypatch):
    from app import raw_logs_worker as worker
    monkeypatch.setattr(worker, 'CATCHUP_MAX_PAGES_PER_CYCLE', 2)
    env.seed('postfix', 750)
    env.cycle(['postfix'])
    assert 'postfix' in worker._catchup_state
    saved = dict(worker._catchup_state['postfix'])

    worker._catchup_state.clear()
    worker.load_catchup_state()
    assert worker._catchup_state['postfix']['offset'] == saved['offset']
    assert worker._catchup_state['postfix']['started_at'] == saved['started_at']

    _drain(env, worker)
    assert _stored('postfix') == 750
    from app.database import get_db_context
    from app.models import SystemSetting
    with get_db_context() as db:
        assert db.query(SystemSetting).filter(
            SystemSetting.key == 'raw_logs_catchup:postfix').first() is None,             'finished walk must clear its persisted state'


def test_an_empty_page_ends_the_walk_only_when_it_repeats(env, monkeypatch):
    from app import raw_logs_worker as worker
    monkeypatch.setattr(worker, 'CATCHUP_MAX_PAGES_PER_CYCLE', 2)
    env.seed('rspamd-history', 300)
    env.cycle(['rspamd-history'])
    real_range = env.get_raw_logs_range
    hiccup = {'armed': True}

    async def flaky(service, offset, page_size):
        if hiccup['armed']:
            hiccup['armed'] = False
            return []
        return await real_range(service, offset, page_size)
    monkeypatch.setattr(env, 'get_raw_logs_range', flaky)

    env.cycle(['rspamd-history'])
    assert 'rspamd-history' in worker._catchup_state, 'one empty page must not end the walk'
    assert worker._catchup_state['rspamd-history'].get('empty_at') == 150

    for _ in range(10):
        if 'rspamd-history' not in worker._catchup_state:
            break
        env.cycle(['rspamd-history'])
    assert _stored('rspamd-history') == 300, 'lines after the hiccup were abandoned'
