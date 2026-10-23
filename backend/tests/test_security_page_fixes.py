"""Security page answers that must match what mailcow and the app really do.

- A single IPv6 address on a Fail2ban list is /128. mailcow's netfilter reads
  2001:db8::1/32 as the network 2001:db8::/32, so it is not the same entry as
  the address 2001:db8::1, and removing the address must leave it alone.
- The Events CSV export applies the same Action and Country filters as the list.
- The Outgoing spam status says whether app passwords are revoked on a block,
  so the page does not promise it when the setting is off.
"""
import asyncio
import csv
import io
import uuid
from datetime import datetime, timedelta

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from fastapi.testclient import TestClient

from app.config import settings
from app.mailcow_api import mailcow_api

MARKER = f'secfix-{uuid.uuid4().hex[:8]}'


def _client():
    from app.main import app
    return TestClient(app)


@pytest.fixture()
def fail2ban_lists(monkeypatch):
    state = {'answer': {'blacklist': '', 'whitelist': ''}, 'written': []}

    async def get_fail2ban():
        return state['answer']

    async def edit_fail2ban(attrs):
        state['written'].append(attrs)
        state['answer'] = {**state['answer'], 'blacklist': attrs['blacklist'], 'whitelist': attrs['whitelist']}
        return [{'type': 'success', 'msg': ['f2b_modified']}]

    monkeypatch.setattr(mailcow_api, 'get_fail2ban', get_fail2ban)
    monkeypatch.setattr(mailcow_api, 'edit_fail2ban', edit_fail2ban)
    return state


def test_removing_an_ipv6_address_leaves_the_slash_32_network_entry(fail2ban_lists):
    fail2ban_lists['answer']['blacklist'] = '2001:db8::1/32\n198.51.100.7/32'
    res = _client().post('/api/fail2ban/remove', json={'ip': '2001:db8::1', 'list': 'blacklist'})
    assert res.json()['status'] == 'success'
    assert fail2ban_lists['written'] == []


def test_a_single_address_entry_is_removed_with_or_without_its_prefix(fail2ban_lists):
    fail2ban_lists['answer']['blacklist'] = '2001:db8::1/128\n198.51.100.7/32\n2001:db8::2'
    client = _client()
    client.post('/api/fail2ban/remove', json={'ip': '2001:db8::1', 'list': 'blacklist'})
    client.post('/api/fail2ban/remove', json={'ip': '198.51.100.7', 'list': 'blacklist'})
    client.post('/api/fail2ban/remove', json={'ip': '2001:db8::2/128', 'list': 'blacklist'})
    assert [w['blacklist'] for w in fail2ban_lists['written']] == [
        '198.51.100.7/32,2001:db8::2', '2001:db8::2', '']


def test_a_slash_32_ipv6_network_is_not_read_as_an_address():
    from app.services.security_addresses import _bare
    assert _bare('2001:db8::/32') == '2001:db8::/32'
    assert _bare('2001:db8::1/128') == '2001:db8::1'
    assert _bare('198.51.100.7/32') == '198.51.100.7'


# ------------------------------------------------------------- Events CSV export

def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


@pytest.fixture()
def netfilter_rows():
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import get_db_context, init_db
    from app.models import NetfilterLog
    init_db()
    rows = [('192.0.2.1', 'ban', 'TL'), ('192.0.2.2', 'banned', 'TL'), ('192.0.2.3', 'warning', 'TL'),
            ('192.0.2.4', 'ban', 'OL'), ('192.0.2.5', 'unban', 'OL')]
    with get_db_context() as db:
        for n, (ip, action, country) in enumerate(rows):
            db.add(NetfilterLog(time=datetime.utcnow() - timedelta(minutes=n), priority=MARKER, ip=ip,
                                action=action, country_code=country, message=f'{MARKER} {ip} {action}'))
        db.commit()
    yield
    with get_db_context() as db:
        db.query(NetfilterLog).filter(NetfilterLog.priority == MARKER).delete(synchronize_session=False)
        db.commit()


def _exported_ips(**params):
    res = _client().get('/api/export/netfilter/csv', params={'search': MARKER, **params})
    assert res.status_code == 200, res.text
    return sorted(r['IP'] for r in csv.DictReader(io.StringIO(res.content.decode('utf-8-sig'))))


def test_the_events_export_keeps_the_action_and_country_filters(netfilter_rows):
    assert _exported_ips() == ['192.0.2.1', '192.0.2.2', '192.0.2.3', '192.0.2.4', '192.0.2.5']
    # Ban also matches the older "banned" lines, as the list does
    assert _exported_ips(action='ban') == ['192.0.2.1', '192.0.2.2', '192.0.2.4']
    assert _exported_ips(country_code='tl') == ['192.0.2.1', '192.0.2.2', '192.0.2.3']
    assert _exported_ips(action='ban', country_code='OL') == ['192.0.2.4']


# ------------------------------------------------------------- Outgoing spam

@pytest.mark.parametrize('revoke', [False, True])
def test_the_outgoing_spam_status_says_whether_app_passwords_are_revoked(monkeypatch, revoke):
    from app.routers import smtp_abuse

    async def no_mailboxes():
        return []
    monkeypatch.setattr(mailcow_api, 'get_mailboxes', no_mailboxes)
    monkeypatch.setattr(smtp_abuse.svc, 'fetch_outbound_counts', lambda *a: {})
    monkeypatch.setattr(smtp_abuse.svc, 'fetch_whitelist', lambda: [])
    monkeypatch.setattr(smtp_abuse.svc, 'fetch_latest_actions', lambda: {})
    monkeypatch.setattr(settings._inner, 'smtp_abuse_revoke_app_passwords', revoke)
    status = asyncio.run(smtp_abuse.get_status(limit=10))
    assert status['revoke_app_passwords'] is revoke


@pytest.mark.parametrize('revoked', [0, 2])
def test_the_operator_alert_says_imap_is_unchanged_only_when_no_app_password_was_revoked(monkeypatch, revoked):
    from app.services import notification_service, smtp_abuse_service
    sent = {}
    monkeypatch.setattr(notification_service, 'notify',
                        lambda subject, text, html, recipient, alert_type: sent.update(text=text))
    asyncio.run(smtp_abuse_service._notify_operator_blocked('user@example.com', 500, revoked))
    assert ('IMAP access is unchanged' in sent['text']) is (revoked == 0)
    assert 'Abuse Protection' not in sent['text'] and 'Security → Settings → Outgoing spam' in sent['text']


@pytest.mark.parametrize('revoked', [0, 2])
def test_the_mailbox_owner_is_told_about_removed_app_passwords_only_when_they_were(monkeypatch, revoked):
    from types import SimpleNamespace
    from app.services import smtp_abuse_service, smtp_service
    sent = {}
    monkeypatch.setattr(smtp_abuse_service, 'settings', SimpleNamespace(
        notification_smtp_configured=True, smtp_abuse_help_address='help@example.com', admin_email='',
        smtp_abuse_window_minutes=60, smtp_abuse_threshold=100))
    monkeypatch.setattr(smtp_service, 'send_notification_email',
                        lambda to, subject, text, html: sent.update(text=text, html=html))
    asyncio.run(smtp_abuse_service._notify_user_blocked('user@example.com', 500, revoked))
    assert ('app passwords were removed' in sent['text']) is (revoked > 0)
    assert ('app passwords were removed' in sent['html']) is (revoked > 0)
    assert 'IMAP is unaffected' not in sent['text']


@pytest.mark.parametrize('revoked', [0, 2])
def test_the_dashboard_alert_says_imap_is_unchanged_only_when_no_app_password_was_revoked(monkeypatch, revoked):
    from app.services import smtp_abuse_service
    added = []

    class FakeDb:
        def add(self, row):
            added.append(row)

        def commit(self):
            pass

    class FakeContext:
        def __enter__(self):
            return FakeDb()

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(smtp_abuse_service, 'get_db_context', FakeContext)
    smtp_abuse_service.record_security_alert('user@example.com', 500, revoked, True)
    detail = added[0].detail
    assert ('IMAP access is unchanged' in detail) is (revoked == 0)
