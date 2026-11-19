"""The Rate Limits page keeps its own, longer history (Rate Limits Retention
Days, never less than the other raw logs) and counts it in the database: no
5000 row cap, a window only as long as the kept history, days in the app
time zone, and the same sender everywhere."""
import uuid
from datetime import datetime, timedelta

import pytest

from app.config import settings

MARK = uuid.uuid4().hex[:8]
DOMAIN = f'rl-{MARK}.example.com'
HEAVY = f'heavy@{DOMAIN}'
OLD = f'old@{DOMAIN}'
HASHED = f'hashed@{DOMAIN}'
MIXED = f'mixed@{DOMAIN}'


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _cleanup():
    from app.database import get_db_context
    from app.models import RawServiceLog
    with get_db_context() as db:
        db.query(RawServiceLog).filter(RawServiceLog.message_hash.like(f'{MARK}%')).delete(synchronize_session=False)
        db.commit()


def _row(service, user, index, when, rl_hash='', sender=None):
    return {
        'service': service, 'time': when, 'message_hash': f'{MARK}-{service}-{index}-{uuid.uuid4().hex[:8]}',
        'raw_data': {'user': user, 'from': sender if sender is not None else user, 'rcpt': f'rcpt{index}@example.net',
                     'qid': f'Q{index}', 'rl_hash': rl_hash, 'header_subject': f'Hit {index}'},
    }


def _insert(rows):
    from app.database import get_db_context
    from app.models import RawServiceLog
    with get_db_context() as db:
        db.bulk_insert_mappings(RawServiceLog, rows)
        db.commit()


@pytest.fixture()
def env():
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import init_db
    init_db()
    _cleanup()
    yield datetime.utcnow()
    _cleanup()


def _events(hours):
    from app.database import get_db_context
    from app.routers.rate_limits import get_rate_limit_events
    with get_db_context() as db:
        return get_rate_limit_events(hours=hours, db=db)


def _groups(data):
    return {g['user']: g for g in data['by_sender']}


def test_more_than_5000_hits_are_counted_exactly(env):
    now = env
    _insert([_row('ratelimited', HEAVY, i, now - timedelta(seconds=30 + i)) for i in range(5200)]
            + [_row('ratelimited', OLD, 10000 + i, now - timedelta(days=40, minutes=i)) for i in range(30)])
    data = _events(720)
    groups = _groups(data)
    assert groups[HEAVY]['events'] == 5200
    assert groups[OLD]['events'] == 30, 'a sender with only older hits is still listed'
    assert len(groups[HEAVY]['recent']) == 5
    assert sum(b['count'] for b in data['by_bucket']) == data['total_events']
    assert data['total_events'] >= 5200


def test_the_newest_hash_is_found_past_the_newest_rows(env):
    now = env
    _insert([_row('ratelimited', HASHED, i, now - timedelta(minutes=i + 1)) for i in range(7)]
            + [_row('ratelimited', HASHED, 99, now - timedelta(hours=3), rl_hash='RLKEEP')])
    assert _groups(_events(24))[HASHED]['last_rl_hash'] == 'RLKEEP'


def test_a_sender_is_the_trimmed_user_else_the_envelope_sender(env):
    from app.database import get_db_context
    from app.routers.rate_limits import get_sender_events
    now = env
    _insert([_row('ratelimited', '  ', 1, now - timedelta(minutes=5), sender=f'  {MIXED.upper()} '),
             _row('ratelimited', f' {MIXED} ', 2, now - timedelta(minutes=6))])
    groups = _groups(_events(24))
    assert groups[MIXED]['events'] == 2
    assert len(groups[MIXED]['recent']) == 2
    assert '' not in groups
    with get_db_context() as db:
        assert get_sender_events(user=MIXED, db=db)['total'] == 2


def test_the_window_is_never_longer_than_the_kept_history(env, monkeypatch):
    monkeypatch.setattr(settings._inner, 'raw_logs_retention_days', 2)
    monkeypatch.setattr(settings._inner, 'rate_limits_retention_days', 90)
    data = _events(8760)
    assert data['hours'] == 2160 and data['windows'] == [24, 168, 720, 2160]
    assert data['retention_days'] == 90
    monkeypatch.setattr(settings._inner, 'rate_limits_retention_days', 400)
    assert _events(8760)['hours'] == 8760
    monkeypatch.setattr(settings._inner, 'rate_limits_retention_days', 3)
    assert _events(720)['windows'] == [24], 'a day is always offered'


def test_the_history_is_never_kept_shorter_than_the_other_raw_logs(monkeypatch):
    monkeypatch.setattr(settings._inner, 'raw_logs_retention_days', 120)
    monkeypatch.setattr(settings._inner, 'rate_limits_retention_days', 90)
    assert settings.rate_limits_retention_effective == 120


def test_days_are_days_of_the_app_time_zone(env, monkeypatch):
    from app.app_time import day_key
    monkeypatch.setattr(settings._inner, 'tz', 'Asia/Jerusalem')
    late = (env - timedelta(days=2)).replace(hour=22, minute=30, second=0, microsecond=0)
    _insert([_row('ratelimited', HEAVY, 1, late)])
    counts = {b['bucket']: b['count'] for b in _events(168)['by_bucket']}
    assert day_key(late) != late.strftime('%Y-%m-%d'), 'the hit falls on the next local day'
    assert counts.get(day_key(late), 0) >= 1


def test_cleanup_keeps_the_rate_limit_log_for_its_own_retention(env, monkeypatch):
    from app.database import get_db_context
    from app.models import RawServiceLog
    from app.raw_logs_worker import _cleanup_raw_service_logs_worker
    now = env
    monkeypatch.setattr(settings._inner, 'raw_logs_retention_days', 2)
    monkeypatch.setattr(settings._inner, 'rate_limits_retention_days', 90)
    _insert([_row('postfix', HEAVY, 1, now - timedelta(days=10)),
             _row('ratelimited', HEAVY, 2, now - timedelta(days=10)),
             _row('ratelimited', HEAVY, 3, now - timedelta(days=100))])

    def kept():
        with get_db_context() as db:
            return sorted((r.service, r.raw_data['qid']) for r in
                          db.query(RawServiceLog).filter(RawServiceLog.message_hash.like(f'{MARK}%')).all())

    _cleanup_raw_service_logs_worker()
    assert kept() == [('ratelimited', 'Q2')]
    # Raw logs kept longer than the rate limit setting: the rate limit log follows them
    _insert([_row('ratelimited', HEAVY, 4, now - timedelta(days=100))])
    monkeypatch.setattr(settings._inner, 'raw_logs_retention_days', 120)
    _cleanup_raw_service_logs_worker()
    assert kept() == [('ratelimited', 'Q2'), ('ratelimited', 'Q4')]
