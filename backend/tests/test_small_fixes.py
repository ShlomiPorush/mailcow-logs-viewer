import asyncio
import importlib
import uuid
from datetime import datetime, timedelta
from unittest.mock import AsyncMock

import dns.resolver
import pytest
from fastapi.testclient import TestClient

import app.models
from app.agent_access import oauth
from app.config import Settings, build_settings, settings
from app.main import app as application
from app.routers import blacklist
from app.routers.rspamd_maps import validate_map_content
from app.services import dns_resolver, dns_resolver_check, geoip_downloader, geoip_service

MARK = f'small-{uuid.uuid4().hex[:8]}'


@pytest.fixture()
def db():
    from app.database import engine, get_db_context, init_db
    try:
        with engine.connect():
            pass
    except Exception:
        pytest.skip('PostgreSQL not available')
    init_db()
    with get_db_context() as session:
        yield session


@pytest.fixture()
def client(monkeypatch):
    for key in ('auth_enabled', 'basic_auth_enabled', 'oauth2_enabled'):
        monkeypatch.setattr(settings._inner, key, False)
    return TestClient(application)


def _resolving(monkeypatch, answers):
    async def resolve(name, record_type='A', timeout=5):
        answer = answers.get(record_type)
        if answer is None:
            raise dns.resolver.NoAnswer()
        return [answer]
    monkeypatch.setattr(dns_resolver, 'resolve', resolve)
    checked = []

    async def check(force=False, ip=None):
        checked.append(ip)
        return {'server_ip': ip, 'status': 'clean', 'checked_at': '2026-11-25T00:00:00Z', 'total_blacklists': 1,
                'listed_count': 0, 'clean_count': 1, 'error_count': 0, 'timeout_count': 0, 'results': []}
    monkeypatch.setattr(blacklist, 'get_blacklist_check_results', check)
    return checked


@pytest.mark.parametrize('answers,address', [
    ({'A': '192.0.2.1'}, '192.0.2.1'), ({'AAAA': '2001:db8::1'}, '2001:db8::1'),
    ({'A': '192.0.2.1', 'AAAA': '2001:db8::1'}, '192.0.2.1')])
def test_a_host_name_is_checked_by_its_address(client, monkeypatch, answers, address):
    checked = _resolving(monkeypatch, answers)
    assert client.post('/api/blacklist/check?host=mx.example.com').json()['server_ip'] == address
    assert checked == [address]


def test_a_host_name_without_an_address_is_an_error_and_never_clean(client, monkeypatch):
    checked = _resolving(monkeypatch, {})
    answer = client.post('/api/blacklist/check?host=mx.example.com').json()
    assert answer['status'] == 'error' and 'mx.example.com' in answer['error']
    assert checked == []


@pytest.mark.parametrize('key,default', [('dmarc_imap_port', 993), ('dmarc_imap_interval', 3600)])
def test_an_empty_dmarc_imap_number_gives_the_default(db, monkeypatch, key, default):
    from app.models import SystemSetting
    monkeypatch.setenv(key.upper(), '')
    assert getattr(Settings(), key) == default
    monkeypatch.delenv(key.upper())
    monkeypatch.setenv('SETTINGS_EDIT_VIA_UI_ENABLED', 'true')
    stored = f'config.{key}'
    db.query(SystemSetting).filter(SystemSetting.key == stored).delete()
    db.add(SystemSetting(key=stored, value=''))
    db.commit()
    try:
        assert getattr(build_settings(db), key) == default
    finally:
        db.query(SystemSetting).filter(SystemSetting.key == stored).delete()
        db.commit()


def test_an_empty_smtp_port_keeps_the_protocol_default(monkeypatch):
    monkeypatch.setenv('SMTP_PORT', '')
    assert Settings().smtp_port is None


def test_the_attempts_overview_counts_every_line_of_the_period(db):
    from sqlalchemy import text
    from app.models import NetfilterLog
    from app.services import security_addresses
    ip = '198.51.100.201'
    try:
        db.execute(text(
            "INSERT INTO netfilter_logs (time, priority, message, ip, action, rule_id) "
            "SELECT :at, :mark, '198.51.100.201 matched rule id 3 (' || n || ')', :ip, 'warning', 3 "
            "FROM generate_series(1, 50010) AS n"), {'at': datetime.utcnow() - timedelta(minutes=5), 'mark': MARK, 'ip': ip})
        db.commit()
        sources, totals = security_addresses.netfilter_sources(db, 1)
        assert sources[ip]['attempts'] == 50010 and totals['attempts'] >= 50010
    finally:
        db.rollback()
        db.query(NetfilterLog).filter(NetfilterLog.priority == MARK).delete(synchronize_session=False)
        db.commit()


def test_geoip_lookups_read_where_the_downloads_go(monkeypatch):
    monkeypatch.setenv('GEOIP_DB_DIR', '/data/geo')
    try:
        importlib.reload(geoip_downloader)
        importlib.reload(geoip_service)
        assert geoip_service.GEOIP_CITY_DB_PATH == geoip_downloader.GEOIP_CITY_DB_PATH == '/data/geo/GeoLite2-City.mmdb'
        assert geoip_service.GEOIP_ASN_DB_PATH == geoip_downloader.GEOIP_ASN_DB_PATH
    finally:
        monkeypatch.delenv('GEOIP_DB_DIR')
        importlib.reload(geoip_downloader)
        importlib.reload(geoip_service)


def test_the_map_editor_says_anchored_only_of_lines_that_are_anchored():
    from app.routers.suppressions import migrate_manual_map_line
    for line in ('user@example.com', 'a+b@example.com', 'us(er)@example.com', 'user|x@example.com', 'plain'):
        said = any('anchored automatically' in problem['error'] for problem in validate_map_content(line))
        assert said == (migrate_manual_map_line(line) != line), line


def test_quarantine_rules_list_delete_rules_first(db, client, monkeypatch):
    from app.mailcow_api import mailcow_api
    from app.models import QuarantineRule
    monkeypatch.setattr(type(mailcow_api), 'has_rw_key', property(lambda self: True))
    try:
        for action in ('release', 'delete', 'release', 'delete'):
            db.add(QuarantineRule(name=f'{MARK}-{uuid.uuid4().hex}', match_type='sender',
                                  match_value='a@example.com', action=action))
            db.commit()
        rules = [r['action'] for r in client.get('/api/quarantine/rules').json()['data'] if r['name'].startswith(MARK)]
        assert rules == ['delete', 'delete', 'release', 'release']
    finally:
        db.query(QuarantineRule).filter(QuarantineRule.name.like(f'{MARK}%')).delete(synchronize_session=False)
        db.commit()


def test_the_device_page_stamps_its_script(monkeypatch):
    monkeypatch.setattr(oauth, 'stamp_asset_versions', lambda html, root: html.replace('?v="', '?v=abc123"'))
    assert b'session-guard.js?v=abc123"' in oauth.code_page().body


@pytest.mark.parametrize('answer,passes', [
    (['127.0.0.2'], True), (['127.0.0.2', '127.0.0.10'], True), (['127.255.255.254'], False),
    (dns.resolver.NXDOMAIN(), False)])
def test_the_resolver_check_expects_the_test_address_to_be_listed(monkeypatch, answer, passes):
    ask = AsyncMock(side_effect=answer) if isinstance(answer, Exception) else AsyncMock(return_value=answer)
    monkeypatch.setattr(dns_resolver_check, 'resolve_for_blacklist', ask)
    assert asyncio.run(dns_resolver_check.test_blacklist_resolve()) is passes
