from conftest import registered_routes

import asyncio
import uuid
from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app.mailcow_api import MailcowAPI, MailcowAPIError

MARKER = uuid.uuid4().hex[:8]
DOMAIN = f'rl-{MARKER}.example'
SENDER = f'loud-{MARKER}@{DOMAIN}'
QUIET = f'quiet-{MARKER}@{DOMAIN}'
SUBJECT = f'rate limit probe {MARKER}'
NEWEST_HASH = f'RLnewest{MARKER}'
OLDER_HASH = f'RLolder{MARKER}'


def test_every_endpoint_is_registered_under_the_api_prefix():
    from app.main import app
    paths = {getattr(route, 'path', '') for route in registered_routes(app)}
    for path in ('/api/rate-limits/events', '/api/rate-limits/sender-events',
                 '/api/rate-limits/limits',
                 '/api/rate-limits/mailbox', '/api/rate-limits/domain',
                 '/api/rate-limits/bulk', '/api/rate-limits/reset'):
        assert path in paths, f'{path} is not registered'


def _client():
    return MailcowAPI()


def test_get_rl_mbox_asks_mailcow_for_the_mailbox_limit(monkeypatch):
    api = _client()
    seen = {}

    async def fake(endpoint, method='GET', **kw):
        seen['endpoint'] = endpoint
        return {'value': '100', 'frame': 'm'}
    monkeypatch.setattr(api, '_make_request', fake)

    out = asyncio.run(api.get_rl_mbox('user@example.com'))
    assert seen['endpoint'] == '/api/v1/get/rl-mbox/user@example.com'
    assert out == {'value': '100', 'frame': 'm'}


def test_get_rl_domain_asks_mailcow_for_the_domain_limit(monkeypatch):
    api = _client()
    seen = {}

    async def fake(endpoint, method='GET', **kw):
        seen['endpoint'] = endpoint
        return {'value': '500', 'frame': 'h'}
    monkeypatch.setattr(api, '_make_request', fake)

    out = asyncio.run(api.get_rl_domain('example.com'))
    assert seen['endpoint'] == '/api/v1/get/rl-domain/example.com'
    assert out == {'value': '500', 'frame': 'h'}


def test_no_limit_is_an_empty_answer(monkeypatch):
    api = _client()

    async def fake(endpoint, method='GET', **kw):
        return {}
    monkeypatch.setattr(api, '_make_request', fake)

    assert asyncio.run(api.get_rl_mbox('user@example.com')) == {}


def test_edit_rl_mbox_posts_the_items_and_attr_payload(monkeypatch):
    api = _client()
    seen = {}

    async def fake(endpoint, method='POST', **kw):
        seen['endpoint'] = endpoint
        seen['method'] = method
        seen['json'] = kw.get('json')
        return [{'type': 'success', 'msg': 'rl_saved'}]
    monkeypatch.setattr(api, '_make_rw_request', fake)

    out = asyncio.run(api.edit_rl_mbox('user@example.com', 100, 'm'))
    assert seen['endpoint'] == '/api/v1/edit/rl-mbox/'
    assert seen['method'] == 'POST'
    assert seen['json'] == {
        'items': ['user@example.com'],
        'attr': {'rl_value': '100', 'rl_frame': 'm'},
    }
    assert out == [{'type': 'success', 'msg': 'rl_saved'}]


def test_edit_rl_domain_posts_the_items_and_attr_payload(monkeypatch):
    api = _client()
    seen = {}

    async def fake(endpoint, method='POST', **kw):
        seen['endpoint'] = endpoint
        seen['json'] = kw.get('json')
        return [{'type': 'success', 'msg': 'rl_saved'}]
    monkeypatch.setattr(api, '_make_rw_request', fake)

    asyncio.run(api.edit_rl_domain('example.com', 500, 'h'))
    assert seen['endpoint'] == '/api/v1/edit/rl-domain/'
    assert seen['json'] == {
        'items': ['example.com'],
        'attr': {'rl_value': '500', 'rl_frame': 'h'},
    }


def test_edit_rl_mboxes_sends_every_mailbox_in_one_call(monkeypatch):
    api = _client()
    seen = {}

    async def fake(endpoint, method='POST', **kw):
        seen.setdefault('calls', 0)
        seen['calls'] += 1
        seen['endpoint'] = endpoint
        seen['json'] = kw.get('json')
        return [{'type': 'success', 'msg': 'rl_saved'}]
    monkeypatch.setattr(api, '_make_rw_request', fake)

    asyncio.run(api.edit_rl_mboxes(
        ['one@example.com', 'two@example.com', 'three@example.net'], 100, 'm'))

    assert seen['calls'] == 1
    assert seen['endpoint'] == '/api/v1/edit/rl-mbox/'
    assert seen['json'] == {
        'items': ['one@example.com', 'two@example.com', 'three@example.net'],
        'attr': {'rl_value': '100', 'rl_frame': 'm'},
    }


def test_edit_rl_domains_sends_every_domain_in_one_call(monkeypatch):
    api = _client()
    seen = {}

    async def fake(endpoint, method='POST', **kw):
        seen.setdefault('calls', 0)
        seen['calls'] += 1
        seen['endpoint'] = endpoint
        seen['json'] = kw.get('json')
        return [{'type': 'success', 'msg': 'rl_saved'}]
    monkeypatch.setattr(api, '_make_rw_request', fake)

    asyncio.run(api.edit_rl_domains(['example.com', 'example.net'], 0, 'h'))

    assert seen['calls'] == 1
    assert seen['endpoint'] == '/api/v1/edit/rl-domain/'
    assert seen['json'] == {
        'items': ['example.com', 'example.net'],
        'attr': {'rl_value': '0', 'rl_frame': 'h'},
    }


def test_removing_a_limit_sends_a_zero_value(monkeypatch):
    api = _client()
    seen = {}

    async def fake(endpoint, method='POST', **kw):
        seen['json'] = kw.get('json')
        return []
    monkeypatch.setattr(api, '_make_rw_request', fake)

    asyncio.run(api.edit_rl_mbox('user@example.com', 0, 'm'))
    assert seen['json']['attr']['rl_value'] == '0'


def test_delete_rl_hash_posts_a_bare_list(monkeypatch):
    api = _client()
    seen = {}

    async def fake(endpoint, method='POST', **kw):
        seen['endpoint'] = endpoint
        seen['json'] = kw.get('json')
        return [{'type': 'success', 'msg': 'rl_hash_removed'}]
    monkeypatch.setattr(api, '_make_rw_request', fake)

    asyncio.run(api.delete_rl_hash('RLabc123'))
    assert seen['endpoint'] == '/api/v1/delete/rlhash'
    assert seen['json'] == ['RLabc123']


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _cleanup():
    from app.database import get_db_context
    from app.models import MailboxStatistics, RawServiceLog
    with get_db_context() as db:
        db.query(RawServiceLog).filter(
            RawServiceLog.service == 'ratelimited',
            RawServiceLog.message_hash.like(f'{MARKER}%')).delete(synchronize_session=False)
        db.query(MailboxStatistics).filter(
            MailboxStatistics.domain == DOMAIN).delete(synchronize_session=False)
        from app.models import SystemSetting
        db.query(SystemSetting).filter(
            SystemSetting.key == 'rate_limit_resets').delete(synchronize_session=False)
        db.commit()


def _log_row(user, index, when, rl_hash):
    from app.models import RawServiceLog
    return RawServiceLog(
        service='ratelimited',
        time=when,
        message_hash=f'{MARKER}-{user}-{index}'[:64],
        raw_data={
            'ip': '203.0.113.9',
            'qid': f'QID{index}{MARKER}',
            'from': user,
            'rcpt': f'rcpt{index}@remote.example',
            'time': int(when.timestamp()),
            'user': user,
            'rl_hash': rl_hash,
            'rl_info': f'mailcow({rl_hash})',
            'rl_name': 'mailcow',
            'message_id': f'<{uuid.uuid4().hex}@{DOMAIN}>',
            'header_from': user,
            'header_subject': SUBJECT,
        },
    )


@pytest.fixture()
def env():
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import init_db, get_db_context
    from app.models import MailboxStatistics
    from app.routers import rate_limits
    init_db()
    _cleanup()
    rate_limits._bust_domain_limit_cache()

    now = datetime.utcnow()
    with get_db_context() as db:
        for index in range(6):
            rl_hash = NEWEST_HASH if index == 0 else OLDER_HASH
            db.add(_log_row(SENDER, index, now - timedelta(minutes=index + 1), rl_hash))
        db.add(_log_row(QUIET, 0, now - timedelta(minutes=90), OLDER_HASH))

        db.add(MailboxStatistics(username=SENDER, domain=DOMAIN, active=True,
                                 rl_value=100, rl_frame='m'))
        db.add(MailboxStatistics(username=QUIET, domain=DOMAIN, active=True))
        db.commit()
    yield
    _cleanup()
    rate_limits._bust_domain_limit_cache()


def _events(hours=168):
    from app.database import get_db_context
    from app.routers.rate_limits import get_rate_limit_events
    with get_db_context() as db:
        return get_rate_limit_events(hours=hours, db=db)


def test_events_are_grouped_by_sender_with_hit_counts(env):
    data = _events()
    groups = {g['user']: g for g in data['by_sender']}
    assert groups[SENDER]['events'] == 6
    assert groups[QUIET]['events'] == 1
    assert data['total_events'] >= 7

    order = [g['user'] for g in data['by_sender']]
    assert order.index(SENDER) < order.index(QUIET), 'busiest sender must come first'


def test_the_latest_hash_is_the_one_offered_for_reset(env):
    groups = {g['user']: g for g in _events()['by_sender']}
    assert groups[SENDER]['last_rl_hash'] == NEWEST_HASH


def test_the_configured_limit_comes_from_the_synced_mailbox_row(env):
    groups = {g['user']: g for g in _events()['by_sender']}
    assert groups[SENDER]['current_limit'] == {'value': 100, 'frame': 'm'}
    assert groups[QUIET]['current_limit'] is None, 'a mailbox without a limit shows none'


def test_each_sender_keeps_a_few_recent_events(env):
    groups = {g['user']: g for g in _events()['by_sender']}
    recent = groups[SENDER]['recent']
    assert len(recent) == 5, 'at most five detail rows per sender'
    assert recent[0]['subject'] == SUBJECT
    assert recent[0]['rcpt'] == 'rcpt0@remote.example'
    assert recent[0]['qid'] == f'QID0{MARKER}'


def test_the_flat_feed_names_the_sender(env):
    flat = [e for e in _events()['events'] if e['user'] in (SENDER, QUIET)]
    assert flat, 'the newest events must appear in the flat feed'
    assert flat[0]['subject'] == SUBJECT


def test_the_window_scopes_the_chart_but_never_the_sender_list(env):
    data = _events(hours=1)
    groups = {g['user']: g for g in data['by_sender']}
    assert SENDER in groups
    assert QUIET in groups, 'the sender list must ignore the window'
    assert groups[QUIET]['events'] == 1

    chart_total = sum(b['count'] for b in data['by_bucket'])
    assert chart_total == data['total_events']
    wide = _events(hours=168)
    assert wide['total_events'] >= data['total_events'] + 1, \
        "QUIET's 90 minute old hit counts in the wide window but not in one hour"


def _sender_events(user):
    from app.database import get_db_context
    from app.routers.rate_limits import get_sender_events
    with get_db_context() as db:
        return get_sender_events(user=user, db=db)


def _seed_extra_hits(count, user=SENDER):
    from app.database import get_db_context
    now = datetime.utcnow()
    with get_db_context() as db:
        for index in range(count):
            db.add(_log_row(user, 100 + index,
                            now - timedelta(minutes=10 + index), OLDER_HASH))
        db.commit()


def test_a_senders_whole_history_is_returned_newest_first(env):
    _seed_extra_hits(4)

    data = _sender_events(SENDER)

    assert data['user'] == SENDER
    assert data['total'] == 10, 'the real number of collected hits'
    assert len(data['events']) == 10, 'every one of them, not a sample'
    times = [event['time'] for event in data['events']]
    assert times == sorted(times, reverse=True), 'newest first'
    assert data['events'][0]['subject'] == SUBJECT
    assert data['events'][0]['rcpt'] == 'rcpt0@remote.example'
    assert data['events'][0]['qid'] == f'QID0{MARKER}'
    assert data['events'][0]['rl_hash'] == NEWEST_HASH


def test_the_history_holds_more_than_the_five_rows_events_carries(env):
    _seed_extra_hits(4)
    groups = {g['user']: g for g in _events()['by_sender']}
    assert len(groups[SENDER]['recent']) == 5
    assert len(_sender_events(SENDER)['events']) == 10


@pytest.mark.parametrize('blank', ['', '   '])
def test_a_request_without_a_sender_is_refused(env, blank):
    with pytest.raises(HTTPException) as exc:
        _sender_events(blank)
    assert exc.value.status_code == 400


def test_an_unknown_sender_is_an_empty_history_not_an_error(env):
    data = _sender_events(f'nobody-{MARKER}@{DOMAIN}')
    assert data['total'] == 0
    assert data['events'] == []


def test_the_sender_is_matched_regardless_of_case(env):
    data = _sender_events(f'  {SENDER.upper()}  ')
    assert data['user'] == SENDER
    assert data['total'] == 6
    assert len(data['events']) == 6


def test_a_very_long_history_is_capped_but_still_counted(env, monkeypatch):
    from app.routers import rate_limits
    _seed_extra_hits(4)
    monkeypatch.setattr(rate_limits, '_SENDER_EVENTS_MAX', 3)

    data = _sender_events(SENDER)

    assert len(data['events']) == 3, 'the newest rows only'
    assert data['total'] == 10, 'the real total, not the capped length'


@pytest.fixture()
def app_zone(monkeypatch):
    from app.config import settings
    def apply(name):
        monkeypatch.setattr(settings._inner, 'tz', name)
    apply('UTC')
    return apply


def test_a_day_or_less_is_bucketed_per_hour_and_anything_longer_per_day(app_zone):
    from app.routers.rate_limits import _bucket_key
    when = datetime(2025, 9, 14, 17, 43, 12)
    assert _bucket_key(when, 'hour') == '2025-09-14T17:00:00Z'
    assert _bucket_key(when, 'day') == '2025-09-14'


def test_a_day_bucket_is_a_day_in_the_app_time_zone(app_zone):
    from app.routers.rate_limits import _bucket_key
    app_zone('Asia/Tokyo')
    when = datetime(2025, 9, 14, 17, 43, 12)
    assert _bucket_key(when, 'day') == '2025-09-15'
    assert _bucket_key(when, 'hour') == '2025-09-14T17:00:00Z'


def test_the_bucket_series_is_zero_filled_across_the_whole_window(app_zone):
    from app.routers.rate_limits import _bucket_series
    since = datetime(2025, 9, 14, 9, 30)
    until = datetime(2025, 9, 14, 12, 5)

    series = _bucket_series(since, until, 'hour', {'2025-09-14T09:00:00Z': 4, '2025-09-14T12:00:00Z': 1})

    assert [b['bucket'] for b in series] == [
        '2025-09-14T09:00:00Z', '2025-09-14T10:00:00Z', '2025-09-14T11:00:00Z', '2025-09-14T12:00:00Z']
    assert [b['count'] for b in series] == [4, 0, 0, 1]


def test_the_bucket_series_covers_every_day_of_a_long_window(app_zone):
    from app.routers.rate_limits import _bucket_series
    since = datetime(2025, 9, 8, 23, 50)
    until = datetime(2025, 9, 14, 0, 10)

    series = _bucket_series(since, until, 'day', {'2025-09-10': 7})

    assert len(series) == 7, 'one bucket per calendar day the window touches'
    assert series[0]['bucket'] == '2025-09-08'
    assert series[-1] == {'bucket': '2025-09-14', 'count': 0}
    assert sum(b['count'] for b in series) == 7


def test_the_day_series_uses_the_days_of_the_app_time_zone(app_zone):
    from app.routers.rate_limits import _bucket_series
    app_zone('Asia/Tokyo')
    series = _bucket_series(datetime(2025, 9, 8, 23, 50), datetime(2025, 9, 14, 0, 10), 'day', {})
    assert [b['bucket'] for b in series] == [
        '2025-09-09', '2025-09-10', '2025-09-11', '2025-09-12', '2025-09-13', '2025-09-14']


def test_the_hour_series_keeps_the_repeated_hour_apart(app_zone):
    from app.routers.rate_limits import _bucket_key, _bucket_series
    app_zone('Europe/Berlin')
    first, second = datetime(2026, 10, 25, 0, 30), datetime(2026, 10, 25, 1, 30)
    counts = {_bucket_key(first, 'hour'): 1}
    counts[_bucket_key(second, 'hour')] = counts.get(_bucket_key(second, 'hour'), 0) + 1
    series = _bucket_series(datetime(2026, 10, 24, 23, 0), datetime(2026, 10, 25, 2, 0), 'hour', counts)
    assert [(b['bucket'], b['count']) for b in series] == [
        ('2026-10-24T23:00:00Z', 0), ('2026-10-25T00:00:00Z', 1),
        ('2026-10-25T01:00:00Z', 1), ('2026-10-25T02:00:00Z', 0)]


def test_a_count_outside_the_generated_range_is_still_returned(app_zone):
    from app.routers.rate_limits import _bucket_series
    since = datetime(2025, 9, 14, 10, 0)
    until = datetime(2025, 9, 14, 11, 0)

    series = _bucket_series(since, until, 'hour', {'2025-09-14T12:00:00Z': 3})

    assert [b['bucket'] for b in series] == [
        '2025-09-14T10:00:00Z', '2025-09-14T11:00:00Z', '2025-09-14T12:00:00Z']
    assert series[-1]['count'] == 3


def test_a_short_window_reports_hourly_buckets(env, app_zone):
    data = _events(hours=24)
    assert data['bucket'] == 'hour'
    buckets = [b['bucket'] for b in data['by_bucket']]
    assert len(buckets) == 25, 'the window plus the hour it started in'
    assert buckets == sorted(buckets), 'oldest first'
    assert len(set(buckets)) == len(buckets), 'no bucket appears twice'
    assert all(len(b) == len('2025-09-14T17:00:00Z') and b[10] == 'T' and b.endswith(':00:00Z') for b in buckets)


def test_a_long_window_reports_daily_buckets(env, app_zone):
    data = _events(hours=168)
    assert data['bucket'] == 'day'
    buckets = [b['bucket'] for b in data['by_bucket']]
    assert len(buckets) == 8, 'seven days plus the day the window started in'
    assert buckets == sorted(buckets)
    assert all(len(b) == len('2025-09-14') for b in buckets)


@pytest.mark.parametrize('hours', [1, 24, 168, 720, 2160, 8760])
def test_every_counted_hit_lands_in_exactly_one_bucket(env, hours):
    data = _events(hours=hours)
    assert sum(b['count'] for b in data['by_bucket']) == data['total_events']


def test_the_buckets_count_the_seeded_hits(env):
    counts = [b['count'] for b in _events(hours=24)['by_bucket']]
    assert counts[-1] + counts[-2] >= 6, 'recent hits belong in the newest buckets'


class FakeMailcow:
    def __init__(self, has_rw_key=True):
        self.has_rw_key = has_rw_key
        self.calls = []

    async def get_rl_domain(self, domain):
        self.calls.append(('get-domain', domain))
        return {'value': '500', 'frame': 'h'}

    async def edit_rl_mbox(self, mailbox, value, frame):
        self.calls.append(('mailbox', mailbox, value, frame))
        return [{'type': 'success', 'msg': 'rl_saved'}]

    async def edit_rl_domain(self, domain, value, frame):
        self.calls.append(('domain', domain, value, frame))
        return [{'type': 'success', 'msg': 'rl_saved'}]

    async def edit_rl_mboxes(self, mailboxes, value, frame):
        self.calls.append(('mailboxes', tuple(mailboxes), value, frame))
        return [{'type': 'success', 'msg': 'rl_saved'}]

    async def edit_rl_domains(self, domains, value, frame):
        self.calls.append(('domains', tuple(domains), value, frame))
        return [{'type': 'success', 'msg': 'rl_saved'}]

    async def delete_rl_hash(self, rl_hash):
        self.calls.append(('reset', rl_hash))
        return [{'type': 'success', 'msg': 'rl_hash_removed'}]


def _fake_client(monkeypatch, **kwargs):
    from app.routers import rate_limits
    fake = FakeMailcow(**kwargs)
    monkeypatch.setattr(rate_limits, 'mailcow_api', fake)
    return fake


def _set_mailbox(value, frame, mailbox=SENDER):
    from app.routers import rate_limits
    return asyncio.run(rate_limits.set_mailbox_limit(
        rate_limits.MailboxLimitRequest(mailbox=mailbox, value=value, frame=frame)))


def _set_domain(value, frame, domain=DOMAIN):
    from app.routers import rate_limits
    return asyncio.run(rate_limits.set_domain_limit(
        rate_limits.DomainLimitRequest(domain=domain, value=value, frame=frame)))


def test_setting_a_mailbox_limit_reaches_mailcow_and_updates_the_local_row(env, monkeypatch):
    from app.database import get_db_context
    from app.models import MailboxStatistics
    fake = _fake_client(monkeypatch)

    result = _set_mailbox(250, 'H', mailbox=SENDER.upper())

    assert fake.calls == [('mailbox', SENDER, 250, 'h')], 'address and frame are normalised'
    assert result['rl_value'] == 250 and result['rl_frame'] == 'h'
    assert result['mailcow_response'] == [{'type': 'success', 'msg': 'rl_saved'}]

    with get_db_context() as db:
        row = db.query(MailboxStatistics).filter(
            MailboxStatistics.username == SENDER).first()
        assert row.rl_value == 250
        assert row.rl_frame == 'h'


def test_removing_a_mailbox_limit_clears_the_local_row(env, monkeypatch):
    from app.database import get_db_context
    from app.models import MailboxStatistics
    fake = _fake_client(monkeypatch)

    result = _set_mailbox(0, 'm')

    assert fake.calls == [('mailbox', SENDER, 0, 'm')]
    assert result['rl_value'] is None and result['rl_frame'] is None
    with get_db_context() as db:
        row = db.query(MailboxStatistics).filter(
            MailboxStatistics.username == SENDER).first()
        assert row.rl_value is None


def test_an_unknown_mailbox_is_refused(env, monkeypatch):
    fake = _fake_client(monkeypatch)
    with pytest.raises(HTTPException) as exc:
        _set_mailbox(10, 'm', mailbox=f'nobody-{MARKER}@{DOMAIN}')
    assert exc.value.status_code == 400
    assert fake.calls == [], 'mailcow must not be called for an unknown mailbox'


def test_an_unknown_frame_is_refused(env, monkeypatch):
    fake = _fake_client(monkeypatch)
    with pytest.raises(HTTPException) as exc:
        _set_mailbox(10, 'week')
    assert exc.value.status_code == 400
    assert fake.calls == []


def test_a_negative_value_is_refused(env, monkeypatch):
    fake = _fake_client(monkeypatch)
    with pytest.raises(HTTPException) as exc:
        _set_mailbox(-5, 'm')
    assert exc.value.status_code == 400
    assert fake.calls == []


def test_setting_a_domain_limit_reaches_mailcow(env, monkeypatch):
    fake = _fake_client(monkeypatch)
    result = _set_domain(500, 'h')
    assert fake.calls == [('domain', DOMAIN, 500, 'h')]
    assert result['rl_value'] == 500 and result['rl_frame'] == 'h'


def test_an_unknown_domain_is_refused(env, monkeypatch):
    fake = _fake_client(monkeypatch)
    with pytest.raises(HTTPException) as exc:
        _set_domain(500, 'h', domain=f'not-ours-{MARKER}.example')
    assert exc.value.status_code == 400
    assert fake.calls == []


def _bulk(value, frame, mailboxes=None, domains=None):
    from app.routers import rate_limits
    return asyncio.run(rate_limits.set_limits_in_bulk(
        rate_limits.BulkLimitRequest(
            mailboxes=mailboxes if mailboxes is not None else [],
            domains=domains if domains is not None else [],
            value=value, frame=frame)))


def _limit_of(mailbox):
    from app.database import get_db_context
    from app.models import MailboxStatistics
    with get_db_context() as db:
        row = db.query(MailboxStatistics).filter(
            MailboxStatistics.username == mailbox).first()
        return (row.rl_value, row.rl_frame)


def test_a_bulk_apply_is_one_mailcow_call_per_kind(env, monkeypatch):
    fake = _fake_client(monkeypatch)

    result = _bulk(250, 'H', mailboxes=[SENDER.upper(), QUIET], domains=[DOMAIN])

    assert fake.calls == [
        ('mailboxes', (SENDER, QUIET), 250, 'h'),
        ('domains', (DOMAIN,), 250, 'h'),
    ], 'one call per kind, addresses and frame normalised'
    assert result['mailboxes_updated'] == 2
    assert result['domains_updated'] == 1
    assert result['skipped'] == []
    assert result['value'] == 250 and result['frame'] == 'h'

    assert _limit_of(SENDER) == (250, 'h')
    assert _limit_of(QUIET) == (250, 'h'), 'the local mirror follows the write'


def test_a_bulk_value_of_zero_clears_every_limit(env, monkeypatch):
    fake = _fake_client(monkeypatch)

    result = _bulk(0, 'm', mailboxes=[SENDER, QUIET])

    assert fake.calls == [('mailboxes', (SENDER, QUIET), 0, 'm')]
    assert result['mailboxes_updated'] == 2
    assert _limit_of(SENDER) == (None, None), 'removing a limit clears the frame too'


def test_an_unknown_name_is_skipped_without_failing_the_others(env, monkeypatch):
    fake = _fake_client(monkeypatch)
    ghost = f'nobody-{MARKER}@{DOMAIN}'
    stranger = f'not-ours-{MARKER}.example'

    result = _bulk(10, 'm', mailboxes=[SENDER, ghost], domains=[DOMAIN, stranger])

    assert fake.calls == [
        ('mailboxes', (SENDER,), 10, 'm'),
        ('domains', (DOMAIN,), 10, 'm'),
    ], 'only the names we know are sent to mailcow'
    assert result['mailboxes_updated'] == 1
    assert result['domains_updated'] == 1
    assert sorted(result['skipped']) == sorted([ghost, stranger])
    assert _limit_of(SENDER) == (10, 'm')


def test_a_bulk_apply_needs_at_least_one_target(env, monkeypatch):
    fake = _fake_client(monkeypatch)
    with pytest.raises(HTTPException) as exc:
        _bulk(10, 'm')
    assert exc.value.status_code == 400
    assert fake.calls == []


def test_a_bulk_apply_needs_a_read_write_key(env, monkeypatch):
    fake = _fake_client(monkeypatch, has_rw_key=False)
    with pytest.raises(HTTPException) as exc:
        _bulk(10, 'm', mailboxes=[SENDER])
    assert exc.value.status_code == 503
    assert fake.calls == []


def test_an_oversized_bulk_request_is_refused(env, monkeypatch):
    from app.routers import rate_limits
    fake = _fake_client(monkeypatch)
    too_many = [f'user{index}-{MARKER}@{DOMAIN}'
                for index in range(rate_limits._BULK_MAX_ITEMS + 1)]

    with pytest.raises(HTTPException) as exc:
        _bulk(10, 'm', mailboxes=too_many)

    assert exc.value.status_code == 400
    assert fake.calls == [], 'the size is refused before anything is looked up'


def test_a_bulk_mailcow_failure_leaves_the_local_rows_alone(env, monkeypatch):
    fake = _fake_client(monkeypatch)

    async def boom(mailboxes, value, frame):
        raise MailcowAPIError('API returned status 500')
    fake.edit_rl_mboxes = boom

    with pytest.raises(HTTPException) as exc:
        _bulk(777, 'd', mailboxes=[SENDER, QUIET], domains=[DOMAIN])

    assert exc.value.status_code == 502
    assert 'API returned status 500' not in str(exc.value.detail)
    assert 'mailcow did not apply the change' in str(exc.value.detail)
    assert _limit_of(SENDER) == (100, 'm'), 'the seeded limit is untouched'
    assert _limit_of(QUIET) == (None, None)


def _reset(rl_hash, monkeypatch_fake):
    from app.routers import rate_limits
    return asyncio.run(rate_limits.reset_rate_limit_counter(
        rate_limits.ReleaseRequest(rl_hash=rl_hash)))


def test_releasing_a_counter_passes_the_hash_to_mailcow(env, monkeypatch):
    fake = _fake_client(monkeypatch)
    result = _reset(NEWEST_HASH, fake)
    assert fake.calls == [('reset', NEWEST_HASH)]
    assert result['rl_hash'] == NEWEST_HASH


@pytest.mark.parametrize('bad', ['', 'notahash', 'RL', 'RL abc', 'RLabc; DROP', '../RLabc'])
def test_a_malformed_rl_hash_is_refused(env, monkeypatch, bad):
    fake = _fake_client(monkeypatch)
    with pytest.raises(HTTPException) as exc:
        _reset(bad, fake)
    assert exc.value.status_code == 400
    assert fake.calls == []


def test_writes_need_a_read_write_key(env, monkeypatch):
    fake = _fake_client(monkeypatch, has_rw_key=False)
    with pytest.raises(HTTPException) as exc:
        _set_mailbox(10, 'm')
    assert exc.value.status_code == 503
    assert fake.calls == []


def test_a_mailcow_failure_is_reported_not_swallowed(env, monkeypatch):
    from app.routers import rate_limits
    fake = _fake_client(monkeypatch)

    async def boom(mailbox, value, frame):
        raise MailcowAPIError('API returned status 500')
    fake.edit_rl_mbox = boom

    with pytest.raises(HTTPException) as exc:
        _set_mailbox(10, 'm')
    assert exc.value.status_code == 502
    assert 'API returned status 500' not in str(exc.value.detail)
    assert 'mailcow did not apply the change' in str(exc.value.detail)


def test_limits_lists_mailbox_and_domain_limits(env, monkeypatch):
    from app.routers import rate_limits
    fake = _fake_client(monkeypatch)

    data = asyncio.run(rate_limits.get_configured_limits())

    mailboxes = {m['username']: m for m in data['mailboxes']}
    assert mailboxes[SENDER]['rl_value'] == 100
    assert mailboxes[SENDER]['rl_frame'] == 'm'
    assert QUIET in mailboxes
    assert mailboxes[QUIET]['rl_value'] is None

    domains = {d['domain']: d for d in data['domains']}
    assert domains[DOMAIN]['rl_value'] == 500
    assert domains[DOMAIN]['rl_frame'] == 'h'
    assert data['domains_error'] is None


def test_domain_limits_are_cached_between_requests(env, monkeypatch):
    from app.routers import rate_limits
    fake = _fake_client(monkeypatch)

    asyncio.run(rate_limits.get_configured_limits())
    first = len(fake.calls)
    asyncio.run(rate_limits.get_configured_limits())
    assert len(fake.calls) == first, 'second read served from the cache'

    rate_limits._bust_domain_limit_cache()
    asyncio.run(rate_limits.get_configured_limits())
    assert len(fake.calls) > first, 'busting the cache refetches'


FEATURE_ID = 'rate-limits'


def _disable(monkeypatch, value):
    from app.config import settings
    monkeypatch.setattr(settings._inner, 'disabled_features', value)
    return settings


def test_rate_limits_is_offered_as_a_toggleable_feature():
    from app.config import Settings
    description = Settings.model_fields['disabled_features'].description
    assert FEATURE_ID in description, description


def test_disabling_rate_limits_turns_the_feature_off(monkeypatch):
    settings = _disable(monkeypatch, 'rate-limits')
    assert settings.is_feature_enabled(FEATURE_ID) is False
    assert FEATURE_ID in settings.disabled_features_set


def test_rate_limits_is_enabled_when_it_is_not_listed(monkeypatch):
    settings = _disable(monkeypatch, 'dmarc,logs')
    assert settings.is_feature_enabled(FEATURE_ID) is True
    assert FEATURE_ID not in settings.disabled_features_set


def test_the_feature_id_survives_spacing_and_case(monkeypatch):
    settings = _disable(monkeypatch, ' DMARC , Rate-Limits ')
    assert settings.is_feature_enabled(FEATURE_ID) is False


def test_api_info_hands_the_disabled_feature_to_the_frontend(monkeypatch):
    from fastapi.testclient import TestClient
    from app.main import app

    _disable(monkeypatch, 'rate-limits')

    body = TestClient(app).get('/api/info').json()

    assert FEATURE_ID in body['disabled_features']


def test_api_info_omits_the_feature_while_it_is_enabled(monkeypatch):
    from fastapi.testclient import TestClient
    from app.main import app

    _disable(monkeypatch, '')

    body = TestClient(app).get('/api/info').json()

    assert body['disabled_features'] == []


def test_disabling_the_feature_leaves_the_endpoints_registered(monkeypatch):
    _disable(monkeypatch, 'rate-limits')

    from app.main import app
    paths = {getattr(route, 'path', '') for route in registered_routes(app)}
    assert '/api/rate-limits/events' in paths
    assert '/api/rate-limits/limits' in paths

def test_a_reset_is_recorded_and_marked_on_the_events_row(env, monkeypatch):
    from app.database import get_db_context
    from app.routers import rate_limits
    fake = _fake_client(monkeypatch)
    with get_db_context() as db:
        result = asyncio.run(rate_limits.reset_rate_limit_counter(
            rate_limits.ReleaseRequest(rl_hash=NEWEST_HASH, user=SENDER)))
        assert result['reset'] is True
        data = rate_limits.get_rate_limit_events(hours=168, db=db)
    group = next(g for g in data['by_sender'] if g['user'] == SENDER)
    assert group.get('last_reset'), 'the reset must be marked on the row'


def _sync_needed():
    from app.scheduler import _mailbox_sync_needed
    return _mailbox_sync_needed()


def test_the_mailbox_sync_runs_when_both_features_are_enabled(monkeypatch):
    _disable(monkeypatch, '')
    assert _sync_needed() is True


def test_the_mailbox_sync_keeps_running_for_rate_limits_alone(monkeypatch):
    _disable(monkeypatch, 'mailbox-stats')
    assert _sync_needed() is True


def test_the_mailbox_sync_keeps_running_for_mailbox_stats_alone(monkeypatch):
    _disable(monkeypatch, 'rate-limits')
    assert _sync_needed() is True


def test_the_mailbox_sync_stops_only_when_both_features_are_off(monkeypatch):
    _disable(monkeypatch, 'mailbox-stats,rate-limits')
    assert _sync_needed() is False


def test_the_mailbox_job_itself_still_runs_with_mailbox_stats_off(monkeypatch):
    from app import scheduler
    _disable(monkeypatch, 'mailbox-stats')
    reached = []

    async def fake_get_mailboxes():
        reached.append(True)
        return []
    monkeypatch.setattr(scheduler.mailcow_api, 'get_mailboxes', fake_get_mailboxes)

    asyncio.run(scheduler.update_mailbox_statistics())
    assert reached, 'the sync must still run while Rate Limits needs it'


def test_the_mailbox_job_stops_when_both_features_are_off(monkeypatch):
    from app import scheduler
    _disable(monkeypatch, 'mailbox-stats,rate-limits')

    async def fake_get_mailboxes():
        raise AssertionError('the mailbox job must not call mailcow')
    monkeypatch.setattr(scheduler.mailcow_api, 'get_mailboxes', fake_get_mailboxes)

    asyncio.run(scheduler.update_mailbox_statistics())


def test_the_alias_job_stays_tied_to_mailbox_stats_alone(monkeypatch):
    from app import scheduler
    _disable(monkeypatch, 'mailbox-stats')

    async def fake_get_aliases():
        raise AssertionError('the alias job must not call mailcow')
    monkeypatch.setattr(scheduler.mailcow_api, 'get_aliases', fake_get_aliases)

    asyncio.run(scheduler.update_alias_statistics())


ALIAS = f'alias-{MARKER}@{DOMAIN}'
TARGET = f'target-{MARKER}@{DOMAIN}'


def _wipe_leftovers():
    from app.database import get_db_context
    from app.models import AliasStatistics, MailboxStatistics, SystemSetting
    with get_db_context() as db:
        db.query(AliasStatistics).filter(
            AliasStatistics.domain == DOMAIN).delete(synchronize_session=False)
        db.query(MailboxStatistics).filter(
            MailboxStatistics.domain == DOMAIN).delete(synchronize_session=False)
        db.query(SystemSetting).filter(
            SystemSetting.key == 'rate_limit_resets').delete(synchronize_session=False)
        db.commit()


@pytest.fixture()
def leftovers():
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import init_db, get_db_context
    from app.models import AliasStatistics, MailboxStatistics, SystemSetting
    init_db()
    _wipe_leftovers()
    with get_db_context() as db:
        db.add(MailboxStatistics(username=TARGET, domain=DOMAIN, active=True,
                                 rl_value=100, rl_frame='m'))
        db.add(AliasStatistics(alias_address=ALIAS, goto=TARGET, domain=DOMAIN,
                               active=True))
        db.add(SystemSetting(key='rate_limit_resets', value='{}'))
        db.commit()
    yield
    _wipe_leftovers()


def _counts():
    from app.database import get_db_context
    from app.models import AliasStatistics, MailboxStatistics, SystemSetting
    with get_db_context() as db:
        return {
            'aliases': db.query(AliasStatistics).count(),
            'mailboxes': db.query(MailboxStatistics).count(),
            'resets': db.query(SystemSetting).filter(
                SystemSetting.key == 'rate_limit_resets').count(),
        }


def _run_cleanup():
    from app.database import get_db_context
    from app.scheduler import cleanup_disabled_feature_data
    with get_db_context() as db:
        cleanup_disabled_feature_data(db)


def test_nothing_is_deleted_while_both_features_are_enabled(leftovers, monkeypatch):
    _disable(monkeypatch, '')
    _run_cleanup()
    after = _counts()
    assert after['aliases'] >= 1
    assert after['mailboxes'] >= 1
    assert after['resets'] == 1


def test_disabling_mailbox_stats_drops_the_alias_rows(leftovers, monkeypatch):
    _disable(monkeypatch, 'mailbox-stats')
    _run_cleanup()
    assert _counts()['aliases'] == 0


def test_the_mailbox_rows_survive_while_rate_limits_still_reads_them(leftovers, monkeypatch):
    _disable(monkeypatch, 'mailbox-stats')
    _run_cleanup()
    assert _counts()['mailboxes'] >= 1


def test_the_mailbox_rows_go_once_both_features_are_off(leftovers, monkeypatch):
    _disable(monkeypatch, 'mailbox-stats,rate-limits')
    _run_cleanup()
    after = _counts()
    assert after['mailboxes'] == 0
    assert after['aliases'] == 0


def test_disabling_rate_limits_drops_the_reset_audit(leftovers, monkeypatch):
    _disable(monkeypatch, 'rate-limits')
    _run_cleanup()
    assert _counts()['resets'] == 0


def test_the_reset_audit_survives_while_rate_limits_is_on(leftovers, monkeypatch):
    _disable(monkeypatch, 'mailbox-stats')
    _run_cleanup()
    assert _counts()['resets'] == 1


def test_running_the_cleanup_twice_changes_nothing(leftovers, monkeypatch):
    _disable(monkeypatch, 'mailbox-stats,rate-limits')
    _run_cleanup()
    first = _counts()
    _run_cleanup()
    assert _counts() == first


def test_a_cleanup_failure_never_reaches_the_caller(monkeypatch):
    from app import scheduler

    def boom(db):
        raise RuntimeError('database on fire')
    monkeypatch.setattr(scheduler, '_run_disabled_feature_cleanup', boom)

    rolled_back = []

    class _Session:
        def rollback(self):
            rolled_back.append(True)

    scheduler.cleanup_disabled_feature_data(_Session())
    assert rolled_back, 'the caller session must be left usable'
