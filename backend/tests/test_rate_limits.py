"""Rate Limits: the mailcow calls behind the page, the grouping of the
collected `ratelimited` log, and the guards on every write.

Nothing here talks to a real mailcow - the API client is exercised through a
monkeypatched `_make_request`, and the router through a fake client object."""
import asyncio
import uuid
from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException
from tenacity import RetryError

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


# ---------- wiring ----------

def test_every_endpoint_is_registered_under_the_api_prefix():
    """Anything outside /api/ is unauthenticated (see test_route_exposure)."""
    from app.main import app
    paths = {getattr(route, 'path', '') for route in app.routes}
    for path in ('/api/rate-limits/events', '/api/rate-limits/limits',
                 '/api/rate-limits/mailbox', '/api/rate-limits/domain',
                 '/api/rate-limits/reset'):
        assert path in paths, f'{path} is not registered'


# ---------- API client: endpoint paths and payloads (no network) ----------

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
    """mailcow answers {} for a mailbox that has no limit - not an error."""
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
    """mailcow's rlhash delete takes the hash as a bare JSON list, not an
    items/attr object."""
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


def test_retry_error_is_normalised_to_mailcow_api_error(monkeypatch):
    """_make_request's retry decorator has no reraise, so after three failures
    tenacity raises RetryError; callers must only ever see MailcowAPIError."""
    api = _client()

    class _Attempt:
        def exception(self):
            return MailcowAPIError('connection refused')

    async def fake(endpoint, method='GET', **kw):
        raise RetryError(_Attempt())
    monkeypatch.setattr(api, '_make_request', fake)

    with pytest.raises(MailcowAPIError) as exc:
        asyncio.run(api.get_rl_mbox('user@example.com'))
    assert 'connection refused' in str(exc.value)


# ---------- database-backed tests ----------

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
        db.commit()


def _log_row(user, index, when, rl_hash):
    """One collected `ratelimited` entry, in the shape mailcow really returns."""
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
        # The loud sender: six hits, the newest one carrying NEWEST_HASH
        for index in range(6):
            rl_hash = NEWEST_HASH if index == 0 else OLDER_HASH
            db.add(_log_row(SENDER, index, now - timedelta(minutes=index + 1), rl_hash))
        # A second sender: one hit, older than an hour, and no configured limit
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
    """The question the page answers: who is hitting a limit, and how often."""
    data = _events()
    groups = {g['user']: g for g in data['by_sender']}
    assert groups[SENDER]['events'] == 6
    assert groups[QUIET]['events'] == 1
    assert data['total_events'] >= 7

    order = [g['user'] for g in data['by_sender']]
    assert order.index(SENDER) < order.index(QUIET), 'busiest sender must come first'


def test_the_latest_hash_is_the_one_offered_for_release(env):
    """Releasing the counter must use the newest hash, not an expired one."""
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


def test_a_short_window_excludes_older_hits(env):
    """QUIET's only hit is 90 minutes old; a one hour window must drop it."""
    groups = {g['user']: g for g in _events(hours=1)['by_sender']}
    assert SENDER in groups
    assert QUIET not in groups or groups[QUIET]['events'] == 0


# ---------- write endpoints ----------

class FakeMailcow:
    """Stands in for the mailcow client inside the router. Records calls so a
    test can assert what would have been sent, and never touches the network."""

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

    async def delete_rl_hash(self, rl_hash):
        self.calls.append(('reset', rl_hash))
        return [{'type': 'success', 'msg': 'rl_hash_removed'}]


def _fake_client(monkeypatch, **kwargs):
    from app.routers import rate_limits
    fake = FakeMailcow(**kwargs)
    monkeypatch.setattr(rate_limits, 'mailcow_api', fake)
    return fake


def _set_mailbox(value, frame, mailbox=SENDER):
    from app.database import get_db_context
    from app.routers import rate_limits
    with get_db_context() as db:
        return asyncio.run(rate_limits.set_mailbox_limit(
            rate_limits.MailboxLimitRequest(mailbox=mailbox, value=value, frame=frame), db=db))


def _set_domain(value, frame, domain=DOMAIN):
    from app.database import get_db_context
    from app.routers import rate_limits
    with get_db_context() as db:
        return asyncio.run(rate_limits.set_domain_limit(
            rate_limits.DomainLimitRequest(domain=domain, value=value, frame=frame), db=db))


def test_setting_a_mailbox_limit_reaches_mailcow_and_updates_the_local_row(env, monkeypatch):
    """The page must show the new limit at once, not after the next sync."""
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


def _reset(rl_hash, monkeypatch_fake):
    from app.routers import rate_limits
    return asyncio.run(rate_limits.release_rate_limit_counter(
        rate_limits.ReleaseRequest(rl_hash=rl_hash)))


def test_releasing_a_counter_passes_the_hash_to_mailcow(env, monkeypatch):
    fake = _fake_client(monkeypatch)
    result = _reset(NEWEST_HASH, fake)
    assert fake.calls == [('reset', NEWEST_HASH)]
    assert result['rl_hash'] == NEWEST_HASH


@pytest.mark.parametrize('bad', ['', 'notahash', 'RL', 'RL abc', 'RLabc; DROP', '../RLabc'])
def test_a_malformed_rl_hash_is_refused(env, monkeypatch, bad):
    """The hash goes straight into a mailcow delete call, so only the real
    shape is accepted."""
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
    assert 'API returned status 500' in str(exc.value.detail)


# ---------- configured limits ----------

def test_limits_lists_mailbox_and_domain_limits(env, monkeypatch):
    from app.database import get_db_context
    from app.routers import rate_limits
    fake = _fake_client(monkeypatch)

    with get_db_context() as db:
        data = asyncio.run(rate_limits.get_configured_limits(db=db))

    mailboxes = {m['username']: m for m in data['mailboxes']}
    assert mailboxes[SENDER]['rl_value'] == 100
    assert mailboxes[SENDER]['rl_frame'] == 'm'
    assert QUIET not in mailboxes, 'only mailboxes that actually have a limit'

    domains = {d['domain']: d for d in data['domains']}
    assert domains[DOMAIN]['rl_value'] == 500
    assert domains[DOMAIN]['rl_frame'] == 'h'
    assert data['domains_error'] is None


def test_domain_limits_are_cached_between_requests(env, monkeypatch):
    """One mailcow round trip per domain is expensive; the page refreshes a
    lot, so a second read must not hit mailcow again."""
    from app.database import get_db_context
    from app.routers import rate_limits
    fake = _fake_client(monkeypatch)

    with get_db_context() as db:
        asyncio.run(rate_limits.get_configured_limits(db=db))
        first = len(fake.calls)
        asyncio.run(rate_limits.get_configured_limits(db=db))
        assert len(fake.calls) == first, 'second read served from the cache'

        rate_limits._bust_domain_limit_cache()
        asyncio.run(rate_limits.get_configured_limits(db=db))
        assert len(fake.calls) > first, 'busting the cache refetches'


# ---------- feature toggle ----------
# Rate Limits is toggleable like every other feature: the id goes into
# `disabled_features`, /api/info hands the list to the frontend, and the
# frontend hides the view. No router in this app gates its own endpoints on a
# feature flag (dmarc, blacklist and mailbox-stats all keep answering while
# disabled), so these tests pin the wiring that actually exists.

FEATURE_ID = 'rate-limits'


def _disable(monkeypatch, value):
    """`settings` is a SettingsWrapper that delegates to a swappable inner
    Settings model, so the field has to be patched on the inner model."""
    from app.config import settings
    monkeypatch.setattr(settings._inner, 'disabled_features', value)
    return settings


def test_rate_limits_is_offered_as_a_toggleable_feature():
    """The valid-id list in the setting's own description is the backend's
    only feature registry - the Settings UI reads it from documentation."""
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
    """This payload is what the frontend gates the view switcher on."""
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
    """Deliberate: gating is UI-side here, exactly as for every other feature.
    If a router-level guard is ever added it must be added for all of them."""
    _disable(monkeypatch, 'rate-limits')

    from app.main import app
    paths = {getattr(route, 'path', '') for route in app.routes}
    assert '/api/rate-limits/events' in paths
    assert '/api/rate-limits/limits' in paths
