"""Security page: attempts grouped by source address, and Fail2ban Allow.

An attempt is a line where netfilter matched a rule; the "N more attempts"
line that follows it must not count again."""
import uuid
from datetime import datetime, timedelta

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app.routers.logs import netfilter_service

MARKER = f'overview-{uuid.uuid4().hex[:8]}'
IP_A = '198.51.100.23'
IP_B = '203.0.113.77'


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _cleanup():
    from app.database import get_db_context
    from app.models import NetfilterLog
    with get_db_context() as db:
        db.query(NetfilterLog).filter(NetfilterLog.priority == MARKER).delete(synchronize_session=False)
        db.commit()


@pytest.fixture()
def client():
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from fastapi.testclient import TestClient
    from app.database import init_db
    from app.main import app
    init_db()
    _cleanup()
    yield TestClient(app)
    _cleanup()


def _add(ip, message, action='warning', rule_id=None, username=None, minutes_ago=5):
    from app.database import get_db_context
    from app.models import NetfilterLog
    with get_db_context() as db:
        db.add(NetfilterLog(time=datetime.utcnow() - timedelta(minutes=minutes_ago), priority=MARKER,
                            message=message, ip=ip, rule_id=rule_id, username=username, action=action))
        db.commit()


def test_service_comes_from_the_log_text():
    assert netfilter_service('1.2.3.4 matched rule id 3 (warning: unknown[1.2.3.4]: SASL LOGIN authentication failed: x)') == ('SMTP auth', True)
    assert netfilter_service('1.2.3.4 matched rule id 4 (warning: non-SMTP command from unknown[1.2.3.4]: GET / HTTP/1.1)') == ('SMTP probe', False)
    assert netfilter_service('imap-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<a>, method=PLAIN, rip=1.2.3.4,') == ('IMAP', True)
    assert netfilter_service('9 more attempts in the next 600 seconds until 1.2.3.4/32 is banned') == (None, False)
    assert netfilter_service(None) == (None, False)


def test_attempts_are_grouped_by_address(client):
    sasl = f'{IP_A} matched rule id 3 (warning: unknown[{IP_A}]: SASL LOGIN authentication failed: (reason unavailable), sasl_username=admin@example.com)'
    for minutes in (5, 10, 15):
        _add(IP_A, sasl, rule_id=3, username='admin@example.com', minutes_ago=minutes)
        _add(IP_A, f'9 more attempts in the next 600 seconds until {IP_A}/32 is banned', minutes_ago=minutes)
    _add(IP_B, f'{IP_B} matched rule id 4 (warning: non-SMTP command from unknown[{IP_B}]: GET / HTTP/1.1)', rule_id=4, minutes_ago=20)
    _add(IP_B, f'Banning {IP_B}/32 for 30 minutes', action='ban', minutes_ago=19)
    _add(IP_B, f'{IP_B} matched rule id 4 (warning: non-SMTP command from unknown[{IP_B}]: x)', rule_id=4, minutes_ago=60 * 30)

    data = client.get('/api/logs/netfilter/overview').json()
    by_ip = {s['ip']: s for s in data['sources']}

    assert by_ip[IP_A]['attempts'] == 3
    assert by_ip[IP_A]['failed_logins'] == 3
    assert by_ip[IP_A]['services'] == ['SMTP auth']
    assert by_ip[IP_A]['usernames'] == ['admin@example.com']
    assert by_ip[IP_A]['last_action'] is None

    # Older than 24 hours does not count; the ban is the last action
    assert by_ip[IP_B]['attempts'] == 1
    assert by_ip[IP_B]['failed_logins'] == 0
    assert by_ip[IP_B]['services'] == ['SMTP probe']
    assert by_ip[IP_B]['last_action'] == 'ban'

    assert data['failed_logins'] >= 3
    assert data['attempts'] >= 4
    assert sum(1 for row in data['latest'] if row['ip'] == IP_A) == 3
    assert all(row['ip'] != IP_B for row in data['latest'])


def test_allow_adds_to_the_whitelist_and_keeps_the_rest(client, monkeypatch):
    from app.mailcow_api import mailcow_api
    saved = {}

    async def fake_get():
        return {'ban_time': 1800, 'ban_time_increment': True, 'max_attempts': 10, 'max_ban_time': 86400,
                'netban_ipv4': 32, 'netban_ipv6': 128, 'retry_window': 600,
                'whitelist': '192.0.2.0/24\n192.0.2.1', 'blacklist': '203.0.113.9/32'}

    async def fake_edit(attrs):
        saved.update(attrs)
        return [{'type': 'success', 'msg': ['fail2ban_edit_ok']}]

    monkeypatch.setattr(mailcow_api, 'get_fail2ban', fake_get)
    monkeypatch.setattr(mailcow_api, 'edit_fail2ban', fake_edit)

    res = client.post('/api/fail2ban/allow', json={'ip': f'{IP_A}/32'})
    assert res.json()['status'] == 'success'
    assert saved['whitelist'] == f'192.0.2.0/24,192.0.2.1,{IP_A}/32'
    assert saved['blacklist'] == '203.0.113.9/32'
    assert saved['ban_time'] == '1800' and saved['ban_time_increment'] == '1'

    saved.clear()
    res = client.post('/api/fail2ban/ban', json={'ip': '192.0.2.50/32'})
    assert res.json()['status'] == 'success'
    assert saved['blacklist'] == '203.0.113.9/32,192.0.2.50/32'
    assert saved['whitelist'] == '192.0.2.0/24,192.0.2.1'

    saved.clear()
    res = client.post('/api/fail2ban/allow', json={'ip': '192.0.2.1'})
    assert 'already' in res.json()['msg']
    assert saved == {}

    assert client.post('/api/fail2ban/allow', json={}).status_code == 400
