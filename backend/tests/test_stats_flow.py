"""The dashboard's mail flow (/api/stats/flow): bars cut at the app time zone's
own edges, through clock changes and in zones half or a quarter of an hour off
UTC; each message counted once in the range, hidden addresses left out, the
bars adding up to the totals; periods of 24, 28 and 30 bars; bad ranges refused."""
import uuid
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app.config import settings
from app.routers.stats_flow import bucket_edges

UTC = timezone.utc


def _utc(text):
    return datetime.fromisoformat(text).replace(tzinfo=UTC)


def test_hours_skip_the_hour_that_does_not_exist_and_repeat_the_one_that_comes_twice():
    berlin = ZoneInfo('Europe/Berlin')
    spring = bucket_edges(_utc('2026-03-28T23:00'), _utc('2026-03-29T03:00'), 'hour', berlin)
    local = [e.astimezone(berlin).strftime('%H:%M') for e in spring]
    assert local == ['00:00', '01:00', '03:00', '04:00']   # 02:00 never happens
    autumn = bucket_edges(_utc('2026-10-24T23:00'), _utc('2026-10-25T03:00'), 'hour', berlin)
    local = [e.astimezone(berlin).strftime('%H:%M') for e in autumn]
    assert local == ['01:00', '02:00', '02:00', '03:00']   # 02:00 twice, an hour apart
    assert autumn[2] - autumn[1] == timedelta(hours=1)


def test_a_day_across_a_clock_change_is_23_or_25_hours():
    berlin = ZoneInfo('Europe/Berlin')
    days = bucket_edges(_utc('2026-03-28T00:00'), _utc('2026-03-30T00:00'), 'day', berlin)
    assert [b - a for a, b in zip(days, days[1:])] == [timedelta(hours=24), timedelta(hours=23)]
    days = bucket_edges(_utc('2026-10-24T00:00'), _utc('2026-10-26T00:00'), 'day', berlin)
    assert [b - a for a, b in zip(days, days[1:])] == [timedelta(hours=24), timedelta(hours=25)]
    quarters = bucket_edges(_utc('2026-10-24T22:00'), _utc('2026-10-25T13:00'), '6h', berlin)
    assert [b - a for a, b in zip(quarters, quarters[1:])] == [timedelta(hours=7), timedelta(hours=6)]


def test_zones_half_and_a_quarter_hour_off_utc_start_their_days_at_their_own_midnight():
    kolkata = bucket_edges(_utc('2026-10-20T12:00'), _utc('2026-10-22T00:00'), 'day', ZoneInfo('Asia/Kolkata'))
    assert all(e.strftime('%H:%M') == '18:30' for e in kolkata)
    kathmandu = bucket_edges(_utc('2026-10-20T12:00'), _utc('2026-10-22T00:00'), 'day', ZoneInfo('Asia/Kathmandu'))
    assert all(e.strftime('%H:%M') == '18:15' for e in kathmandu)
    hours = bucket_edges(_utc('2026-10-20T00:00'), _utc('2026-10-20T03:00'), 'hour', ZoneInfo('Asia/Kolkata'))
    assert all(e.minute == 30 for e in hours)


def test_a_day_whose_midnight_does_not_exist_starts_at_its_first_moment():
    santiago = ZoneInfo('America/Santiago')
    days = bucket_edges(_utc('2025-09-05T12:00'), _utc('2025-09-08T12:00'), 'day', santiago)
    starts = [e.astimezone(santiago) for e in days]
    assert [s.date().isoformat() for s in starts] == ['2025-09-05', '2025-09-06', '2025-09-07', '2025-09-08']
    assert starts[2].strftime('%H:%M') == '01:00'   # the clocks skip from 00:00 to 01:00 that night


# ---------- counting, against the database ----------

MARK = uuid.uuid4().hex[:8]
SENDER = f'flow-{MARK}@example.com'
HIDDEN = f'hidden-{MARK}@example.net'


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


@pytest.fixture()
def client(monkeypatch):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    for key in ('auth_enabled', 'basic_auth_enabled', 'oauth2_enabled'):
        monkeypatch.setattr(settings._inner, key, False)
    monkeypatch.setattr(settings._inner, 'tz', 'UTC')
    monkeypatch.setattr(settings._inner, 'blacklist_emails', HIDDEN)
    from app.database import init_db, get_db_context
    from app.models import MessageCorrelation
    init_db()

    def cleanup():
        with get_db_context() as db:
            db.query(MessageCorrelation).filter(MessageCorrelation.sender == SENDER).delete(synchronize_session=False)
            db.commit()
    cleanup()
    yield
    cleanup()


def _add(subject, at, message_id=None, recipient='r@example.org', status='delivered', first_seen=True):
    from app.database import get_db_context
    from app.models import MessageCorrelation
    with get_db_context() as db:
        db.add(MessageCorrelation(correlation_key=uuid.uuid4().hex, sender=SENDER, recipient=recipient, message_id=message_id,
                                  direction='outbound', subject=f'{subject} {MARK}', final_status=status,
                                  first_seen=at if first_seen else None, last_seen=at, created_at=at))
        db.commit()


def _flow(query):
    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app).get(f'/api/stats/flow?{query}')


def test_a_message_counts_once_hidden_addresses_not_and_the_bars_add_up(client):
    base = datetime(2025, 1, 10, 10, 0)
    mid = f'<two-{MARK}@example.com>'
    _add('first', base + timedelta(minutes=10), mid)
    _add('again', base + timedelta(hours=1, minutes=10), mid, recipient='other@example.org')   # same message, next hour
    _add('alone', base + timedelta(hours=1, minutes=20), status='bounced')
    _add('hidden', base + timedelta(minutes=30), recipient=HIDDEN)
    response = _flow(f'from={base.isoformat()}Z&to={(base + timedelta(hours=3)).isoformat()}Z&bucket=hour')
    assert response.status_code == 200, response.text
    data = response.json()
    bars = data['buckets']
    assert [b['start'] for b in bars] == ['2025-01-10T10:00:00.000000Z', '2025-01-10T11:00:00.000000Z', '2025-01-10T12:00:00.000000Z']
    assert [b['messages'] for b in bars] == [1, 1, 0]          # the two deliveries of one message: once, in its first bar
    assert [b['deliveries'] for b in bars] == [1, 2, 0]
    assert [b['blocked'] for b in bars] == [0, 1, 0]
    assert data['totals']['messages'] == 2 and data['totals']['deliveries'] == 3
    assert bars[0]['end_inclusive'] == '2025-01-10T10:59:59.999999Z'
    assert data['to_inclusive'] == '2025-01-10T12:59:59.999999Z'


def test_a_delivery_without_first_seen_is_not_counted_as_messages_leaves_it_out_of_a_range(client):
    base = datetime(2025, 1, 12, 10, 0)
    _add('seen', base + timedelta(minutes=5))
    _add('stored only', base + timedelta(minutes=15), first_seen=False)
    data = _flow(f'from={base.isoformat()}Z&to={(base + timedelta(hours=1)).isoformat()}Z&bucket=hour').json()
    assert data['totals']['messages'] == 1 and data['totals']['deliveries'] == 1


def test_periods_have_their_bars_and_the_one_before(client):
    for period, count, bucket in (('24h', 24, 'hour'), ('7d', 28, '6h'), ('30d', 30, 'day')):
        data = _flow(f'period={period}').json()
        assert len(data['buckets']) == count and data['bucket'] == bucket, (period, len(data['buckets']))
        assert data['buckets'][-1]['partial'] is True and data['buckets'][0]['partial'] is False
        before = _flow(f'period={period}&previous=true').json()
        assert len(before['buckets']) == count and before['to'] == data['from']


def test_bad_ranges_are_refused(client):
    assert _flow('').status_code == 422
    assert _flow('period=1y').status_code == 422
    assert _flow('from=2030-01-02T00:00:00Z&to=2030-01-01T00:00:00Z&bucket=hour').status_code == 422
    # Longer than 62 days, all in the past: refused for its length, not for the future
    assert _flow('from=2025-01-01T00:00:00Z&to=2025-03-05T00:00:00Z&bucket=day').status_code == 422
    assert _flow('from=2025-01-01T00:00:00Z&to=2025-03-03T00:00:00Z&bucket=day').status_code == 200
    assert _flow('from=yesterday&to=2030-01-01T00:00:00Z&bucket=hour').status_code == 422
    assert _flow('from=2030-01-01T00:00:00Z&to=2030-01-02T00:00:00Z&bucket=week').status_code == 422


def test_a_range_snaps_to_the_nearest_bars_at_least_one(client):
    def span(a, b):
        data = _flow(f'from=2025-01-10T{a}Z&to=2025-01-10T{b}Z&bucket=hour').json()
        return data['from'], data['to'], len(data['buckets'])
    # A pinch from 10:45 to 12:15 shows 11:00 to 12:00, not 10:00 to 13:00
    assert span('10:45:00', '12:15:00') == ('2025-01-10T11:00:00.000000Z', '2025-01-10T12:00:00.000000Z', 1)
    # Less than half a bar still shows the bar it is in
    assert span('10:10:00', '10:20:00') == ('2025-01-10T10:00:00.000000Z', '2025-01-10T11:00:00.000000Z', 1)
    # Whole bars stay as they are
    assert span('08:00:00', '11:00:00') == ('2025-01-10T08:00:00.000000Z', '2025-01-10T11:00:00.000000Z', 3)
