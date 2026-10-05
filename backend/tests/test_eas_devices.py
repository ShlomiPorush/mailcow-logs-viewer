"""ActiveSync devices read from SOGo's access log: the line parser, the
idempotent upsert, retention, the job's feature gate and the /api/devices list.
Fake addresses only."""
import asyncio
from datetime import datetime, timedelta

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app.services.eas_devices import collect_devices, parse_eas_line

EAS = '/SOGo/Microsoft-Server-ActiveSync'


def line(query, remote='203.0.113.7', status=200, pid='[61]: ', method='POST'):
    return f'{pid}{remote} "{method} {EAS}?{query} HTTP/1.1" {status} 13/0 0.012 - - 0 - 15'


# --- parser -----------------------------------------------------------------

def test_a_plain_ping_gives_user_device_type_command_ip_and_status():
    parsed = parse_eas_line(line('User=jane%40example.com&DeviceId=ABC123&DeviceType=iPhone&Cmd=Ping'))
    assert parsed == {
        'username': 'jane@example.com', 'device_id': 'ABC123', 'device_type': 'iPhone',
        'last_command': 'Ping', 'last_ip': '203.0.113.7', 'last_status': 200,
    }


def test_parameter_order_and_case_do_not_matter():
    parsed = parse_eas_line(line('cmd=Sync&deviceid=XYZ&user=Jane@Example.com&devicetype=SAMSUNGSMG991B'))
    assert (parsed['username'], parsed['device_id'], parsed['last_command']) == ('jane@example.com', 'XYZ', 'Sync')


def test_an_ipv6_client_is_kept():
    assert parse_eas_line(line('User=jane@example.com&DeviceId=A', remote='2001:db8::7'))['last_ip'] == '2001:db8::7'


def test_a_hostname_in_the_client_slot_is_not_shown_as_an_ip():
    parsed = parse_eas_line(line('User=jane@example.com&DeviceId=A', remote='nginx-mailcow.example.test'))
    assert parsed is not None and parsed['last_ip'] is None


def test_a_forwarded_list_gives_the_client_address():
    parsed = parse_eas_line(line('User=jane@example.com&DeviceId=A', remote='203.0.113.7, 198.51.100.2'))
    assert parsed['last_ip'] == '203.0.113.7'


def test_a_line_in_the_shape_a_real_mailcow_logs_it():
    # Seen on a live mailcow: nginx's X-Forwarded-For repeats the client
    message = ('[126]: 203.0.113.7, 203.0.113.7 "POST /SOGo/Microsoft-Server-ActiveSync?Cmd=Sync'
               '&User=jane%40example.com&DeviceId=androidc1234567890&DeviceType=Android HTTP/1.1" '
               '200 0/69 0.234 - - 288K - 13')
    assert parse_eas_line(message) == {
        'username': 'jane@example.com', 'device_id': 'androidc1234567890', 'device_type': 'Android',
        'last_command': 'Sync', 'last_ip': '203.0.113.7', 'last_status': 200,
    }
    assert parse_eas_line('[126]: <0x0x5555d9fdb620[SOGoActiveSyncDispatcher]> Change detected during Sync, we push the content.') is None


def test_a_line_without_the_pid_prefix_still_parses():
    assert parse_eas_line(line('User=jane@example.com&DeviceId=A', pid=''))['device_id'] == 'A'


def test_a_failed_login_keeps_its_status():
    assert parse_eas_line(line('User=jane@example.com&DeviceId=A&Cmd=Sync', status=401))['last_status'] == 401


def test_a_missing_device_type_and_command_stay_empty():
    parsed = parse_eas_line(line('User=jane@example.com&DeviceId=A'))
    assert parsed['device_type'] is None and parsed['last_command'] is None


@pytest.mark.parametrize('message', [
    # The base64 query form names no user
    f'[61]: 203.0.113.7 "POST {EAS}?jAAJBAp2MTQwRGV2aWNlAApTbWFydFBob25l HTTP/1.1" 200 13/0 0.012 - - 0 - 15',
    line('DeviceId=A&Cmd=Ping'),
    line('User=jane@example.com&Cmd=Ping'),
    f'[61]: 203.0.113.7 "OPTIONS {EAS} HTTP/1.1" 200 0/0 0.001 - - 0 - 1',
    '[115]: watchdog.example.test "GET /SOGo.index/ HTTP/1.1" 200 2578/0 0.003 - - 0 - 12',
    '[61]: 203.0.113.7 "POST /SOGo/so/jane@example.com/Mail/0/folderINBOX/changes HTTP/1.1" 200 312/64 0.041 - - 0',
    'ActiveSync: some unrelated notice',
    '',
])
def test_lines_that_name_no_device_are_skipped(message):
    assert parse_eas_line(message) is None


def test_the_batch_keeps_the_newest_request_and_the_oldest_time():
    entries = [
        {'time': '1000', 'message': line('User=jane@example.com&DeviceId=A&DeviceType=iPhone&Cmd=Sync')},
        {'time': '3000', 'message': line('User=jane@example.com&DeviceId=A&DeviceType=iPhone&Cmd=Ping', remote='203.0.113.9')},
        {'time': '2000', 'message': line('User=jane@example.com&DeviceId=A&DeviceType=iPhone&Cmd=MoveItems')},
        {'time': 'bad', 'message': line('User=jane@example.com&DeviceId=B')},
        {'time': '1500', 'message': '[115]: watchdog.example.test "GET /SOGo.index/ HTTP/1.1" 200 1/0 0.003'},
    ]
    [device] = collect_devices(entries)
    assert device['last_command'] == 'Ping' and device['last_ip'] == '203.0.113.9'
    assert device['first_seen'] == datetime(1970, 1, 1, 0, 16, 40)
    assert device['last_seen'] == datetime(1970, 1, 1, 0, 50, 0)


# --- database ---------------------------------------------------------------

USER = 'eas-test@example.test'


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


@pytest.fixture()
def db():
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import SessionLocal, init_db
    from app.models import EasDevice
    init_db()
    session = SessionLocal()

    def cleanup():
        session.query(EasDevice).filter(EasDevice.username.like('eas-test%')).delete(synchronize_session=False)
        session.commit()

    cleanup()
    yield session
    cleanup()
    session.close()


def _entry(when, query, **kw):
    return {'time': str(int(when.timestamp())), 'message': line(query, **kw)}


def _rows(db):
    from app.models import EasDevice
    db.expire_all()
    return db.query(EasDevice).filter(EasDevice.username.like('eas-test%')).order_by(EasDevice.device_id).all()


def test_overlapping_cycles_leave_one_row_with_the_right_times(db):
    from app.services.eas_devices import store_devices
    t0 = datetime(2026, 10, 1, 12, 0, 0)
    q = f'User={USER}&DeviceId=A&DeviceType=iPhone'
    first = [_entry(t0, q + '&Cmd=Sync'), _entry(t0 + timedelta(minutes=5), q + '&Cmd=Ping')]
    second = first[1:] + [_entry(t0 + timedelta(minutes=9), q + '&Cmd=Ping', remote='203.0.113.9')]
    store_devices(db, collect_devices(first))
    store_devices(db, collect_devices(second))
    store_devices(db, collect_devices(second))   # the same page read again
    [row] = _rows(db)
    assert row.first_seen == t0
    assert row.last_seen == t0 + timedelta(minutes=9)
    assert (row.last_command, row.last_ip) == ('Ping', '203.0.113.9')


def test_an_older_line_read_late_does_not_overwrite_the_newest_request(db):
    from app.services.eas_devices import store_devices
    t0 = datetime(2026, 10, 1, 12, 0, 0)
    q = f'User={USER}&DeviceId=A'
    store_devices(db, collect_devices([_entry(t0, q + '&DeviceType=iPhone&Cmd=Ping', remote='203.0.113.9')]))
    store_devices(db, collect_devices([_entry(t0 - timedelta(hours=1), q + '&DeviceType=iPad&Cmd=Sync', status=401)]))
    [row] = _rows(db)
    assert row.first_seen == t0 - timedelta(hours=1)
    assert row.last_seen == t0
    assert (row.device_type, row.last_command, row.last_ip, row.last_status) == ('iPhone', 'Ping', '203.0.113.9', 200)


def test_a_newer_line_without_a_type_keeps_the_known_type(db):
    from app.services.eas_devices import store_devices
    t0 = datetime(2026, 10, 1, 12, 0, 0)
    store_devices(db, collect_devices([_entry(t0, f'User={USER}&DeviceId=A&DeviceType=iPhone&Cmd=Sync')]))
    store_devices(db, collect_devices([_entry(t0 + timedelta(minutes=1), f'User={USER}&DeviceId=A&Cmd=Ping', remote='nginx.example.test')]))
    [row] = _rows(db)
    assert (row.device_type, row.last_command, row.last_ip) == ('iPhone', 'Ping', '203.0.113.7')


@pytest.mark.parametrize('retention,kept', [(0, ['A', 'B']), (90, ['B'])])
def test_retention_forgets_devices_not_seen_for_that_long(db, retention, kept):
    from app.services.eas_devices import delete_stale_devices, store_devices
    now = datetime.utcnow()
    store_devices(db, collect_devices([
        _entry(now - timedelta(days=120), f'User={USER}&DeviceId=A'),
        _entry(now - timedelta(days=10), f'User={USER}&DeviceId=B'),
    ]))
    delete_stale_devices(db, retention)
    assert [r.device_id for r in _rows(db)] == kept


def test_the_job_does_nothing_while_the_feature_is_off(monkeypatch):
    from app import scheduler
    from app.config import settings

    async def must_not_fetch(*a, **k):
        raise AssertionError('a disabled feature must not read the SOGo log')
    monkeypatch.setattr(settings._inner, 'disabled_features', 'devices')
    monkeypatch.setattr(scheduler.mailcow_api, 'get_raw_logs', must_not_fetch)
    asyncio.run(scheduler.update_eas_devices())


def test_the_job_records_devices_from_the_sogo_log(db, monkeypatch):
    from app import scheduler
    from app.config import settings
    now = datetime.utcnow().replace(microsecond=0)
    requested = []

    async def sogo_log(service, count):
        requested.append(service)
        return [_entry(now, f'User={USER}&DeviceId=A&DeviceType=iPhone&Cmd=Ping')]
    monkeypatch.setattr(settings._inner, 'disabled_features', '')
    monkeypatch.setattr(scheduler.mailcow_api, 'get_raw_logs', sogo_log)
    asyncio.run(scheduler.update_eas_devices())
    assert requested == ['sogo']
    [row] = _rows(db)
    assert (row.username, row.device_type, row.last_seen) == (USER, 'iPhone', now)


def test_the_list_filters_sorts_and_counts(db):
    from fastapi.testclient import TestClient
    from app.main import app
    from app.services.eas_devices import store_devices
    now = datetime.utcnow()
    store_devices(db, collect_devices([
        _entry(now - timedelta(minutes=5), f'User={USER}&DeviceId=PHONE&DeviceType=iPhone&Cmd=Ping'),
        _entry(now - timedelta(days=40), f'User=eas-test-2@example.test&DeviceId=TAB&DeviceType=iPad&Cmd=Sync'),
    ]))
    client = TestClient(app)

    body = client.get('/api/devices', params={'search': 'eas-test', 'sort_by': 'last_seen', 'sort_dir': 'asc'}).json()
    assert [d['device_id'] for d in body['items']] == ['TAB', 'PHONE']
    assert body['items'][1]['last_seen'].endswith('Z')

    recent = client.get('/api/devices', params={'search': 'eas-test', 'seen': 'recent'}).json()
    assert [d['device_id'] for d in recent['items']] == ['PHONE']
    stale = client.get('/api/devices', params={'search': 'eas-test', 'seen': 'stale'}).json()
    assert [d['device_id'] for d in stale['items']] == ['TAB']
    typed = client.get('/api/devices', params={'search': 'eas-test', 'device_type': 'iPad'}).json()
    assert [d['device_id'] for d in typed['items']] == ['TAB']
    assert {'iPhone', 'iPad'} <= set(body['device_types'])

    # A wildcard typed into the search is a character, not a pattern
    assert client.get('/api/devices', params={'search': 'eas_test'}).json()['total'] == 0
    assert client.get('/api/devices', params={'sort_by': 'nope'}).status_code == 422
