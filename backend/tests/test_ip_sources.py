import uuid
from datetime import datetime, timezone, timedelta

import pytest

from app.config import Settings, settings
from app.routers import domains
from app.services import blacklist_service


class FakeTXT:
    def __init__(self, text):
        self.strings = (text.encode(),)


class FakeAddr:
    def __init__(self, value):
        self._value = value

    def __str__(self):
        return self._value


def _set_spf_sources(monkeypatch, server_ip=False, transports=False,
                     relayhosts=False, manual='', dmarc_history=False):
    monkeypatch.setattr(settings._inner, 'domain_spf_source_server_ip', server_ip)
    monkeypatch.setattr(settings._inner, 'domain_spf_source_transports', transports)
    monkeypatch.setattr(settings._inner, 'domain_spf_source_relayhosts', relayhosts)
    monkeypatch.setattr(settings._inner, 'domain_spf_source_manual_hosts', manual)
    monkeypatch.setattr(settings._inner, 'domain_spf_source_dmarc_history', dmarc_history)


def _set_blacklist_sources(monkeypatch, server_ip=True, transports=True,
                           relayhosts=True, manual=''):
    monkeypatch.setattr(settings._inner, 'blacklist_source_server_ip', server_ip)
    monkeypatch.setattr(settings._inner, 'blacklist_source_transports', transports)
    monkeypatch.setattr(settings._inner, 'blacklist_source_relayhosts', relayhosts)
    monkeypatch.setattr(settings._inner, 'blacklist_source_manual_hosts', manual)


def test_source_setting_defaults_preserve_released_behavior():
    s = Settings()
    assert s.blacklist_source_server_ip is True
    assert s.blacklist_source_transports is True
    assert s.blacklist_source_relayhosts is True
    assert s.blacklist_source_manual_hosts == ''
    assert s.domain_spf_source_server_ip is True
    assert s.domain_spf_source_transports is False
    assert s.domain_spf_source_relayhosts is False
    assert s.domain_spf_source_manual_hosts == ''
    assert s.domain_spf_source_dmarc_history is False


def test_manual_hosts_accepts_ips_and_hostnames_and_normalizes():
    s = Settings(blacklist_source_manual_hosts=' 203.0.113.10 , 2001:db8::10 , Relay.Example.COM ')
    assert s.blacklist_source_manual_hosts == '203.0.113.10,2001:db8::10,relay.example.com'
    assert s.blacklist_source_manual_hosts_list == ['203.0.113.10', '2001:db8::10', 'relay.example.com']


def test_spf_manual_hosts_uses_same_validation():
    s = Settings(domain_spf_source_manual_hosts='198.51.100.7,mail.example.org')
    assert s.domain_spf_source_manual_hosts_list == ['198.51.100.7', 'mail.example.org']


@pytest.mark.parametrize('bad', [
    'not a host',
    '[relay.example.com]',
    'host_name.example.com',
    'bad!chars.example.com',
    '-leadinghyphen.example.com',
])
def test_manual_hosts_rejects_garbage(bad):
    with pytest.raises(Exception) as exc_info:
        Settings(blacklist_source_manual_hosts=f'203.0.113.10,{bad}')
    assert 'invalid' in str(exc_info.value).lower()
    with pytest.raises(Exception):
        Settings(domain_spf_source_manual_hosts=bad)


def test_manual_hosts_empty_means_no_entries():
    s = Settings(blacklist_source_manual_hosts='')
    assert s.blacklist_source_manual_hosts == ''
    assert s.blacklist_source_manual_hosts_list == []


def test_manual_hosts_list_is_lenient_at_use_time():
    s = Settings.model_construct(blacklist_source_manual_hosts='203.0.113.10,bad host,relay.example.com')
    assert s.blacklist_source_manual_hosts_list == ['203.0.113.10', 'relay.example.com']
    s = Settings.model_construct(domain_spf_source_manual_hosts='2001:db8::10,[broken]')
    assert s.domain_spf_source_manual_hosts_list == ['2001:db8::10']


@pytest.mark.asyncio
async def test_ip4_mechanism_matches_ipv4():
    ok, method = await domains.check_ip_in_spf(
        'example.com', '203.0.113.7', 'v=spf1 ip4:203.0.113.0/24 -all')
    assert ok is True
    assert method == 'ip4:203.0.113.0/24'


@pytest.mark.asyncio
async def test_ip6_mechanism_matches_ipv6_network():
    ok, method = await domains.check_ip_in_spf(
        'example.com', '2001:db8:1234::1', 'v=spf1 ip6:2001:db8::/32 -all')
    assert ok is True
    assert method == 'ip6:2001:db8::/32'


@pytest.mark.asyncio
async def test_ip6_mechanism_matches_compressed_vs_exploded_forms():
    ok, _ = await domains.check_ip_in_spf(
        'example.com', '2001:0db8:0000:0000:0000:0000:0000:0001',
        'v=spf1 ip6:2001:db8::1 -all')
    assert ok is True


@pytest.mark.asyncio
async def test_ip_version_mismatch_does_not_match():
    ok, _ = await domains.check_ip_in_spf(
        'example.com', '203.0.113.7', 'v=spf1 ip6:2001:db8::/32 -all')
    assert ok is False
    ok, _ = await domains.check_ip_in_spf(
        'example.com', '2001:db8::1', 'v=spf1 ip4:203.0.113.0/24 -all')
    assert ok is False


@pytest.mark.asyncio
async def test_invalid_ip_to_check_returns_unauthorized():
    ok, method = await domains.check_ip_in_spf(
        'example.com', 'not-an-ip', 'v=spf1 ip4:203.0.113.0/24 -all')
    assert ok is False
    assert method is None


@pytest.mark.asyncio
async def test_a_mechanism_uses_aaaa_for_ipv6(monkeypatch):
    queries = []

    async def fake_resolve(query, record_type='TXT', timeout=5):
        queries.append((query, record_type))
        if record_type == 'AAAA':
            return [FakeAddr('2001:db8::25')]
        return []

    monkeypatch.setattr(domains, 'resolve_dns_with_fallback', fake_resolve)
    ok, method = await domains.check_ip_in_spf(
        'example.com', '2001:DB8::25', 'v=spf1 a -all')
    assert ok is True
    assert method == 'a'
    assert ('example.com', 'AAAA') in queries


@pytest.mark.asyncio
async def test_a_mechanism_still_uses_a_records_for_ipv4(monkeypatch):
    queries = []

    async def fake_resolve(query, record_type='TXT', timeout=5):
        queries.append((query, record_type))
        if record_type == 'A':
            return [FakeAddr('203.0.113.25')]
        return []

    monkeypatch.setattr(domains, 'resolve_dns_with_fallback', fake_resolve)
    ok, method = await domains.check_ip_in_spf(
        'example.com', '203.0.113.25', 'v=spf1 a -all')
    assert ok is True
    assert method == 'a'
    assert ('example.com', 'A') in queries


class FakeMailcowAPI:
    def __init__(self, transports=None, relayhosts=None,
                 fail_transports=False, fail_relayhosts=False):
        self.transports = transports or []
        self.relayhosts = relayhosts or []
        self.fail_transports = fail_transports
        self.fail_relayhosts = fail_relayhosts
        self.transport_calls = 0
        self.relayhost_calls = 0

    async def get_transports(self):
        self.transport_calls += 1
        if self.fail_transports:
            raise RuntimeError('mailcow down')
        return self.transports

    async def get_relayhosts(self):
        self.relayhost_calls += 1
        if self.fail_relayhosts:
            raise RuntimeError('mailcow down')
        return self.relayhosts


def _dns_a_map(monkeypatch, mapping):
    async def fake_resolve(query, record_type='TXT', timeout=5):
        if record_type == 'A':
            return [FakeAddr(ip) for ip in mapping.get(query, [])]
        return []
    monkeypatch.setattr(domains, 'resolve_dns_with_fallback', fake_resolve)


@pytest.mark.asyncio
async def test_spf_sources_all_disabled_yields_empty(monkeypatch):
    _set_spf_sources(monkeypatch)
    api = FakeMailcowAPI(fail_transports=True, fail_relayhosts=True)
    monkeypatch.setattr(domains, 'mailcow_api', api)
    assert await domains.get_spf_source_ips() == []
    assert api.transport_calls == 0 and api.relayhost_calls == 0


@pytest.mark.asyncio
async def test_spf_sources_server_ip_only(monkeypatch):
    _set_spf_sources(monkeypatch, server_ip=True)
    monkeypatch.setattr(domains, '_server_ip_cache', '203.0.113.5')
    assert await domains.get_spf_source_ips() == [
        {'ip': '203.0.113.5', 'source': 'auto-detected'}
    ]


@pytest.mark.asyncio
async def test_spf_sources_transports_resolve_all_public_ips(monkeypatch):
    _set_spf_sources(monkeypatch, transports=True)
    api = FakeMailcowAPI(transports=[
        {'active': '1', 'nexthop': '[relay.example.com]:587'},
        {'active': '0', 'nexthop': 'inactive.example.com'},
        {'active': 1, 'nexthop': '81.169.145.99'},
    ])
    monkeypatch.setattr(domains, 'mailcow_api', api)
    _dns_a_map(monkeypatch, {'relay.example.com': ['81.169.145.97', '81.169.145.98', '10.0.0.1']})

    result = await domains.get_spf_source_ips()
    assert result == [
        {'ip': '81.169.145.97', 'source': 'transport'},
        {'ip': '81.169.145.98', 'source': 'transport'},
        {'ip': '81.169.145.99', 'source': 'transport'},
    ]


@pytest.mark.asyncio
async def test_spf_sources_relayhosts(monkeypatch):
    _set_spf_sources(monkeypatch, relayhosts=True)
    api = FakeMailcowAPI(relayhosts=[{'active': '1', 'hostname': 'smtp.example.net:25'}])
    monkeypatch.setattr(domains, 'mailcow_api', api)
    _dns_a_map(monkeypatch, {'smtp.example.net': ['87.106.1.30']})

    assert await domains.get_spf_source_ips() == [
        {'ip': '87.106.1.30', 'source': 'relayhost'}
    ]
    assert api.transport_calls == 0


@pytest.mark.asyncio
async def test_spf_sources_manual_hosts_literals_and_hostnames(monkeypatch):
    _set_spf_sources(monkeypatch, manual='203.0.113.10,2001:db8::10,relay.example.com')
    _dns_a_map(monkeypatch, {'relay.example.com': ['81.169.145.97']})

    assert await domains.get_spf_source_ips() == [
        {'ip': '203.0.113.10', 'source': 'configured'},
        {'ip': '2001:db8::10', 'source': 'configured'},
        {'ip': '81.169.145.97', 'source': 'configured'},
    ]


@pytest.mark.asyncio
async def test_spf_sources_dedupe_first_source_wins(monkeypatch):
    _set_spf_sources(monkeypatch, server_ip=True, transports=True, manual='81.169.145.97')
    monkeypatch.setattr(domains, '_server_ip_cache', '81.169.145.97')
    api = FakeMailcowAPI(transports=[{'active': '1', 'nexthop': '81.169.145.97'}])
    monkeypatch.setattr(domains, 'mailcow_api', api)

    assert await domains.get_spf_source_ips() == [
        {'ip': '81.169.145.97', 'source': 'auto-detected'}
    ]


@pytest.mark.asyncio
async def test_spf_sources_mailcow_failure_does_not_abort_other_sources(monkeypatch):
    _set_spf_sources(monkeypatch, server_ip=True, transports=True, relayhosts=True)
    monkeypatch.setattr(domains, '_server_ip_cache', '203.0.113.5')
    api = FakeMailcowAPI(fail_transports=True, fail_relayhosts=True)
    monkeypatch.setattr(domains, 'mailcow_api', api)

    assert await domains.get_spf_source_ips() == [
        {'ip': '203.0.113.5', 'source': 'auto-detected'}
    ]


def _fake_txt_resolver(spf_text):
    async def fake_resolve(query, record_type='TXT', timeout=5):
        if record_type == 'TXT':
            return [FakeTXT(spf_text)]
        return []
    return fake_resolve


@pytest.mark.asyncio
async def test_check_spf_record_validates_provided_sources(monkeypatch):
    _set_spf_sources(monkeypatch)
    monkeypatch.setattr(
        domains, 'resolve_dns_with_fallback',
        _fake_txt_resolver('v=spf1 ip4:203.0.113.10 ip6:2001:db8::/32 -all'))

    result = await domains.check_spf_record('example.com', [
        {'ip': '203.0.113.10', 'source': 'configured'},
        {'ip': '2001:db8::10', 'source': 'configured'},
    ])
    assert result['status'] == 'success'
    assert 'authorized' in result['message'].lower()
    assert result['checked_ips'] == [
        {'ip': '203.0.113.10', 'source': 'configured', 'authorized': True},
        {'ip': '2001:db8::10', 'source': 'configured', 'authorized': True},
    ]


@pytest.mark.asyncio
async def test_check_spf_record_flags_unauthorized_ips(monkeypatch):
    _set_spf_sources(monkeypatch)
    monkeypatch.setattr(
        domains, 'resolve_dns_with_fallback',
        _fake_txt_resolver('v=spf1 ip4:198.51.100.1 -all'))

    result = await domains.check_spf_record('example.com', [
        {'ip': '203.0.113.10', 'source': 'configured'},
        {'ip': '2001:db8::10', 'source': 'transport'},
    ])
    assert result['status'] == 'error'
    assert 'NOT authorized' in result['message']
    assert '203.0.113.10' in result['message']
    assert '2001:db8::10' in result['message']


@pytest.mark.asyncio
async def test_check_spf_record_resolves_sources_itself_when_not_provided(monkeypatch):
    _set_spf_sources(monkeypatch, server_ip=True)
    monkeypatch.setattr(
        domains, 'resolve_dns_with_fallback',
        _fake_txt_resolver('v=spf1 ip4:203.0.113.99 -all'))
    monkeypatch.setattr(domains, '_server_ip_cache', '203.0.113.99')

    result = await domains.check_spf_record('example.com')
    assert result['status'] == 'success'
    assert result['checked_ips'] == [
        {'ip': '203.0.113.99', 'source': 'auto-detected', 'authorized': True},
    ]


@pytest.mark.asyncio
async def test_checked_ips_empty_when_no_source_yields_an_ip(monkeypatch):
    _set_spf_sources(monkeypatch, server_ip=True)
    monkeypatch.setattr(
        domains, 'resolve_dns_with_fallback',
        _fake_txt_resolver('v=spf1 ip4:203.0.113.99 -all'))
    monkeypatch.setattr(domains, '_server_ip_cache', None)

    async def no_ip():
        return None
    monkeypatch.setattr(domains, 'init_server_ip', no_ip)

    result = await domains.check_spf_record('example.com')
    assert result['status'] == 'success'
    assert result['checked_ips'] == []


@pytest.mark.asyncio
async def test_checked_ips_absent_when_no_spf_record(monkeypatch):
    _set_spf_sources(monkeypatch)

    async def no_txt(query, record_type='TXT', timeout=5):
        return []
    monkeypatch.setattr(domains, 'resolve_dns_with_fallback', no_txt)

    result = await domains.check_spf_record('example.com')
    assert result['status'] == 'error'
    assert 'checked_ips' not in result


@pytest.mark.asyncio
async def test_dmarc_history_ips_get_source_label_and_are_checked(monkeypatch):
    _set_spf_sources(monkeypatch, dmarc_history=True)
    monkeypatch.setattr(
        domains, 'resolve_dns_with_fallback',
        _fake_txt_resolver('v=spf1 ip4:203.0.113.50 ip6:2001:db8::/32 -all'))
    monkeypatch.setattr(
        domains, 'get_recent_dmarc_passing_source_ips',
        lambda domain, days=30, limit=20: {
            'ips': ['203.0.113.50', '2001:db8::66', '198.51.100.99'],
            'reports_found': True,
            'newest_report_age_days': 1.0,
        })

    result = await domains.check_spf_record('example.com', [])
    assert result['checked_ips'] == [
        {'ip': '203.0.113.50', 'source': 'dmarc-history', 'authorized': True},
        {'ip': '2001:db8::66', 'source': 'dmarc-history', 'authorized': True},
        {'ip': '198.51.100.99', 'source': 'dmarc-history', 'authorized': False},
    ]
    assert result['status'] == 'error'


@pytest.mark.asyncio
async def test_dmarc_history_does_not_duplicate_existing_source_ips(monkeypatch):
    _set_spf_sources(monkeypatch, dmarc_history=True)
    monkeypatch.setattr(
        domains, 'resolve_dns_with_fallback',
        _fake_txt_resolver('v=spf1 ip4:203.0.113.50 -all'))
    monkeypatch.setattr(
        domains, 'get_recent_dmarc_passing_source_ips',
        lambda domain, days=30, limit=20: {
            'ips': ['203.0.113.50'], 'reports_found': True, 'newest_report_age_days': 0.5,
        })

    result = await domains.check_spf_record('example.com', [
        {'ip': '203.0.113.50', 'source': 'configured'},
    ])
    assert result['checked_ips'] == [
        {'ip': '203.0.113.50', 'source': 'configured', 'authorized': True},
    ]


@pytest.mark.asyncio
async def test_dmarc_history_no_reports_note_is_additive_only(monkeypatch):
    _set_spf_sources(monkeypatch, dmarc_history=True)
    monkeypatch.setattr(
        domains, 'resolve_dns_with_fallback',
        _fake_txt_resolver('v=spf1 ip4:203.0.113.50 -all'))
    monkeypatch.setattr(
        domains, 'get_recent_dmarc_passing_source_ips',
        lambda domain, days=30, limit=20: {
            'ips': [], 'reports_found': False, 'newest_report_age_days': None,
        })

    result = await domains.check_spf_record('example.com', [
        {'ip': '203.0.113.50', 'source': 'configured'},
    ])
    assert result['status'] == 'success'
    assert any('no reports are available yet' in w for w in result['warnings'])


def test_dmarc_history_notes_staleness_logic():
    notes = domains.dmarc_history_notes(
        {'ips': [], 'reports_found': False, 'newest_report_age_days': None})
    assert len(notes) == 1 and 'no reports are available yet' in notes[0]

    notes = domains.dmarc_history_notes(
        {'ips': ['a'], 'reports_found': True, 'newest_report_age_days': 10.2})
    assert len(notes) == 1 and '10 days old' in notes[0]

    notes = domains.dmarc_history_notes(
        {'ips': ['a'], 'reports_found': True, 'newest_report_age_days': 2.0})
    assert notes == []


def _postgres_available():
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


@pytest.fixture()
def dmarc_db():
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import engine, get_db_context
    from app.database import Base
    from app.models import DMARCReport, DMARCRecord
    Base.metadata.create_all(bind=engine, tables=[DMARCReport.__table__, DMARCRecord.__table__])
    with get_db_context() as db:
        db.query(DMARCRecord).delete()
        db.query(DMARCReport).delete()
        db.commit()
    yield
    with get_db_context() as db:
        db.query(DMARCRecord).delete()
        db.query(DMARCReport).delete()
        db.commit()


def _add_report(db, domain, begin_offset_days, end_offset_days, records):
    from app.models import DMARCReport, DMARCRecord
    now = datetime.now(timezone.utc)
    report = DMARCReport(
        report_id=str(uuid.uuid4()),
        domain=domain,
        org_name='test-org',
        begin_date=int((now - timedelta(days=begin_offset_days)).timestamp()),
        end_date=int((now - timedelta(days=end_offset_days)).timestamp()),
    )
    db.add(report)
    db.flush()
    for source_ip, spf in records:
        db.add(DMARCRecord(dmarc_report_id=report.id, source_ip=source_ip,
                           count=1, spf_result=spf))
    db.commit()


def test_dmarc_history_query_filters(dmarc_db):
    from app.database import get_db_context
    with get_db_context() as db:
        _add_report(db, 'example.com', 2, 1, [
            ('203.0.113.50', 'pass'),
            ('203.0.113.50', 'pass'),
            ('2001:db8::66', 'pass'),
            ('198.51.100.99', 'fail'),
            ('198.51.100.98', None),
        ])
        _add_report(db, 'example.com', 45, 44, [('192.0.2.77', 'pass')])
        _add_report(db, 'other.com', 2, 1, [('192.0.2.88', 'pass')])

    result = domains.get_recent_dmarc_passing_source_ips('example.com')
    assert sorted(result['ips']) == sorted(['203.0.113.50', '2001:db8::66'])
    assert len(result['ips']) == len(set(result['ips']))
    assert result['reports_found'] is True
    assert result['newest_report_age_days'] == pytest.approx(1.0, abs=0.1)


def test_dmarc_history_query_respects_limit(dmarc_db):
    from app.database import get_db_context
    with get_db_context() as db:
        _add_report(db, 'example.com', 2, 1,
                    [(f'203.0.113.{i}', 'pass') for i in range(1, 30)])

    result = domains.get_recent_dmarc_passing_source_ips('example.com', limit=20)
    assert len(result['ips']) == 20


def test_dmarc_history_query_no_reports(dmarc_db):
    result = domains.get_recent_dmarc_passing_source_ips('example.com')
    assert result == {'ips': [], 'reports_found': False, 'newest_report_age_days': None}


def test_dmarc_history_query_stale_reports(dmarc_db):
    from app.database import get_db_context
    with get_db_context() as db:
        _add_report(db, 'example.com', 12, 11, [('203.0.113.50', 'pass')])

    result = domains.get_recent_dmarc_passing_source_ips('example.com')
    assert result['ips'] == ['203.0.113.50']
    assert result['reports_found'] is True
    assert result['newest_report_age_days'] == pytest.approx(11.0, abs=0.1)
    assert domains.dmarc_history_notes(result)


def test_dmarc_history_indexes_exist(dmarc_db):
    from sqlalchemy import inspect
    from app.database import engine
    report_indexes = {i['name'] for i in inspect(engine).get_indexes('dmarc_reports')}
    record_indexes = {i['name'] for i in inspect(engine).get_indexes('dmarc_records')}
    assert 'idx_dmarc_report_domain_date' in report_indexes
    assert 'idx_dmarc_record_report' in record_indexes


def test_auto_monitor_entries_include_manual_hosts_and_wan(monkeypatch):
    _set_blacklist_sources(monkeypatch, manual='2001:db8::10,relay.example.com')
    monkeypatch.setattr(domains, '_server_ip_cache', '203.0.113.5')

    entries = blacklist_service.get_auto_monitor_entries()
    assert entries == [
        ('2001:db8::10', 'config'),
        ('relay.example.com', 'config'),
        ('203.0.113.5', 'system'),
    ]


def test_auto_monitor_entries_skip_wan_when_disabled(monkeypatch):
    _set_blacklist_sources(monkeypatch, server_ip=False, manual='2001:db8::10')
    monkeypatch.setattr(domains, '_server_ip_cache', '203.0.113.5')

    entries = blacklist_service.get_auto_monitor_entries()
    assert entries == [('2001:db8::10', 'config')]


def test_auto_monitor_entries_empty_when_wan_disabled_and_nothing_configured(monkeypatch):
    _set_blacklist_sources(monkeypatch, server_ip=False)
    monkeypatch.setattr(domains, '_server_ip_cache', '203.0.113.5')

    assert blacklist_service.get_auto_monitor_entries() == []


def test_auto_monitor_entries_dedupe_wan_matching_manual_ip(monkeypatch):
    _set_blacklist_sources(monkeypatch, manual='203.0.113.5')
    monkeypatch.setattr(domains, '_server_ip_cache', '203.0.113.5')

    assert blacklist_service.get_auto_monitor_entries() == [('203.0.113.5', 'config')]


def test_reverse_ip_ipv4():
    assert blacklist_service.reverse_ip('1.2.3.4') == '4.3.2.1'


def test_reverse_ip_ipv6_nibble_format():
    assert blacklist_service.reverse_ip('2001:db8::1') == (
        '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2'
    )


def test_reverse_ip_non_ip_keeps_legacy_behavior():
    assert blacklist_service.reverse_ip('foo.bar') == 'bar.foo'


class _FakeQuery:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class _FakeDB:
    def __init__(self, rows):
        self.rows = rows
        self.added = []
        self.committed = False

    def query(self, model):
        return _FakeQuery(self.rows)

    def add(self, obj):
        self.added.append(obj)

    def commit(self):
        self.committed = True


def _host_row(hostname, source, active=True):
    from app.models import MonitoredHost
    row = MonitoredHost()
    row.hostname = hostname
    row.source = source
    row.active = active
    return row


def test_reconcile_adds_manual_entries_to_nonempty_table(monkeypatch):
    _set_blacklist_sources(monkeypatch, manual='198.51.100.7,relay.example.com')
    monkeypatch.setattr(domains, '_server_ip_cache', '203.0.113.5')

    db = _FakeDB([_host_row('203.0.113.5', 'system')])
    changed = blacklist_service.reconcile_monitored_hosts(db)

    assert changed and db.committed
    assert [(r.hostname, r.source) for r in db.added] == [
        ('198.51.100.7', 'config'),
        ('relay.example.com', 'config'),
    ]
    assert db.rows[0].active is True


def test_reconcile_deactivates_wan_when_server_ip_source_disabled(monkeypatch):
    _set_blacklist_sources(monkeypatch, server_ip=False)
    monkeypatch.setattr(domains, '_server_ip_cache', '203.0.113.5')

    db = _FakeDB([_host_row('203.0.113.5', 'system')])
    changed = blacklist_service.reconcile_monitored_hosts(db)

    assert changed and db.rows[0].active is False and not db.added


def test_reconcile_deactivates_removed_manual_entry_and_reactivates_returning_one(monkeypatch):
    _set_blacklist_sources(monkeypatch, server_ip=False, manual='2001:db8::10')
    monkeypatch.setattr(domains, '_server_ip_cache', None)

    stale = _host_row('198.51.100.7', 'config', active=True)
    returning = _host_row('2001:db8::10', 'config', active=False)
    db = _FakeDB([stale, returning])
    changed = blacklist_service.reconcile_monitored_hosts(db)

    assert changed
    assert stale.active is False
    assert returning.active is True
    assert not db.added


def test_reconcile_handles_sync_resolved_manual_hostname_rows(monkeypatch):
    _set_blacklist_sources(monkeypatch, server_ip=False, manual='relay.example.com')
    monkeypatch.setattr(domains, '_server_ip_cache', None)

    resolved_a = _host_row('198.51.100.7', 'config:relay.example.com')
    resolved_b = _host_row('198.51.100.8', 'config:relay.example.com')
    db = _FakeDB([resolved_a, resolved_b])
    changed = blacklist_service.reconcile_monitored_hosts(db)

    assert changed is False
    assert resolved_a.active is True and resolved_b.active is True
    assert not db.added

    _set_blacklist_sources(monkeypatch, server_ip=False, manual='')
    changed = blacklist_service.reconcile_monitored_hosts(db)
    assert changed
    assert resolved_a.active is False and resolved_b.active is False


def test_reconcile_no_change_is_a_noop(monkeypatch):
    _set_blacklist_sources(monkeypatch, manual='198.51.100.7')
    monkeypatch.setattr(domains, '_server_ip_cache', '203.0.113.5')

    db = _FakeDB([_host_row('198.51.100.7', 'config'), _host_row('203.0.113.5', 'system')])
    changed = blacklist_service.reconcile_monitored_hosts(db)

    assert changed is False and db.committed is False and not db.added


def test_reconcile_reactivates_system_row_when_wan_detection_unavailable(monkeypatch):
    _set_blacklist_sources(monkeypatch)
    monkeypatch.setattr(domains, '_server_ip_cache', None)

    row = _host_row('203.0.113.5', 'system', active=False)
    db = _FakeDB([row])
    changed = blacklist_service.reconcile_monitored_hosts(db)

    assert changed and row.active is True and not db.added


def test_applicable_blacklists_ipv4_gets_full_list():
    assert blacklist_service.applicable_blacklists('203.0.113.5') == blacklist_service.BLACKLISTS


def test_applicable_blacklists_hostname_gets_full_list():
    assert blacklist_service.applicable_blacklists('mail.example.com') == blacklist_service.BLACKLISTS


def test_applicable_blacklists_ipv6_only_capable_zones():
    zones = blacklist_service.applicable_blacklists('2001:db8::25')
    assert zones, "IPv6 must still be checked against something"
    assert all(bl.get('ipv6') for bl in zones)
    names = {bl['name'] for bl in zones}
    assert 'Spamhaus ZEN' in names
    assert 'Barracuda' not in names
    assert 'SpamCop' not in names


def test_dead_rbls_removed():
    zones = {bl['zone'] for bl in blacklist_service.BLACKLISTS}
    assert not any('sorbs' in z for z in zones)
    assert 'cbl.abuseat.org' not in zones


def test_parse_nexthop_bracket_with_port():
    from app.scheduler import parse_nexthop_host
    assert parse_nexthop_host('[relay.example.com]:587') == 'relay.example.com'


def test_parse_nexthop_all_forms():
    from app.scheduler import parse_nexthop_host
    assert parse_nexthop_host('relay.example.com') == 'relay.example.com'
    assert parse_nexthop_host('relay.example.com:25') == 'relay.example.com'
    assert parse_nexthop_host('[relay.example.com]') == 'relay.example.com'
    assert parse_nexthop_host('[198.51.100.7]:25') == '198.51.100.7'
    assert parse_nexthop_host('  [Relay.Example.COM]:587  ') == 'relay.example.com'
    assert parse_nexthop_host('') == ''


def test_reconcile_deactivates_transport_and_relayhost_rows_when_toggled_off(monkeypatch):
    monkeypatch.setattr(settings._inner, 'blacklist_source_server_ip', True)
    monkeypatch.setattr(settings._inner, 'blacklist_source_transports', False)
    monkeypatch.setattr(settings._inner, 'blacklist_source_relayhosts', False)
    monkeypatch.setattr(settings._inner, 'blacklist_source_manual_hosts', '')
    monkeypatch.setattr(domains, '_server_ip_cache', '203.0.113.5')

    t = _host_row('9.9.9.9', 'transport:pool.relay.example')
    r = _host_row('9.9.9.10', 'relayhost')
    wan = _host_row('203.0.113.5', 'system')
    db = _FakeDB([t, r, wan])
    changed = blacklist_service.reconcile_monitored_hosts(db)

    assert changed
    assert t.active is False and r.active is False
    assert wan.active is True


def test_reconcile_never_reactivates_sync_deactivated_rows(monkeypatch):
    from datetime import datetime, timedelta
    monkeypatch.setattr(settings._inner, 'blacklist_source_server_ip', False)
    monkeypatch.setattr(settings._inner, 'blacklist_source_transports', True)
    monkeypatch.setattr(settings._inner, 'blacklist_source_relayhosts', True)
    monkeypatch.setattr(settings._inner, 'blacklist_source_manual_hosts', '')
    monkeypatch.setattr(domains, '_server_ip_cache', None)

    deleted_in_mailcow = _host_row('9.9.9.9', 'relayhost:old.relay.example', active=False)
    deleted_in_mailcow.last_seen = datetime.utcnow() - timedelta(hours=1)
    stale = _host_row('9.9.9.10', 'transport', active=False)
    stale.last_seen = datetime.utcnow() - timedelta(days=30)
    db = _FakeDB([deleted_in_mailcow, stale])
    changed = blacklist_service.reconcile_monitored_hosts(db)

    assert deleted_in_mailcow.active is False, \
        "row deactivated by sync must stay inactive until sync itself re-adds it"
    assert stale.active is False
    assert changed is False and not db.added


def test_non_dnsbl_answer_is_never_reported_as_listed(monkeypatch):
    import asyncio

    class FakeAnswer:
        def __init__(self, ips): self._ips = ips
        def __iter__(self): return iter(self._ips)

    async def fake_resolve(query, rdtype='A', timeout=10):
        return FakeAnswer(['92.242.140.2'])

    import app.services.dns_resolver as dnsr
    monkeypatch.setattr(dnsr, 'resolve_for_blacklist', fake_resolve)
    result = asyncio.run(blacklist_service.check_ip_in_blacklist(
        '203.0.113.5', {'name': 'Test RBL', 'zone': 'rbl.test', 'info_url': ''}, 0))
    assert result['listed'] is False
    assert result['status'] == 'error'
    assert 'rewrite' in result['response']


def test_real_127_answer_still_reported_as_listed(monkeypatch):
    import asyncio

    class FakeAnswer:
        def __init__(self, ips): self._ips = ips
        def __iter__(self): return iter(self._ips)

    async def fake_resolve(query, rdtype='A', timeout=10):
        return FakeAnswer(['127.0.0.2'])

    import app.services.dns_resolver as dnsr
    monkeypatch.setattr(dnsr, 'resolve_for_blacklist', fake_resolve)
    result = asyncio.run(blacklist_service.check_ip_in_blacklist(
        '203.0.113.5', {'name': 'Test RBL', 'zone': 'rbl.test', 'info_url': ''}, 0))
    assert result['listed'] is True and result['response'] == '127.0.0.2'


def test_cleanup_purges_only_long_inactive_monitored_hosts():
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    import asyncio
    from datetime import datetime, timedelta
    from app.database import init_db, get_db_context
    from app.models import MonitoredHost
    from app.scheduler import cleanup_old_logs

    init_db()
    old = datetime.utcnow() - timedelta(days=45)
    fresh = datetime.utcnow() - timedelta(days=2)
    with get_db_context() as db:
        db.query(MonitoredHost).filter(
            MonitoredHost.hostname.like('purge-test-%')).delete(synchronize_session=False)
        db.add(MonitoredHost(hostname='purge-test-dead', source='relayhost',
                             active=False, last_seen=old))
        db.add(MonitoredHost(hostname='purge-test-recent', source='transport',
                             active=False, last_seen=fresh))
        db.add(MonitoredHost(hostname='purge-test-active', source='system',
                             active=True, last_seen=old))
        db.commit()

    asyncio.run(cleanup_old_logs())

    with get_db_context() as db:
        remaining = {h.hostname for h in db.query(MonitoredHost).filter(
            MonitoredHost.hostname.like('purge-test-%')).all()}
        db.query(MonitoredHost).filter(
            MonitoredHost.hostname.like('purge-test-%')).delete(synchronize_session=False)
        db.commit()
    assert remaining == {'purge-test-recent', 'purge-test-active'}, remaining


@pytest.mark.parametrize('answer,expected_listed,expected_status', [
    ('127.0.0.1', False, 'error'),
    ('127.0.0.2', True, 'listed'),
    ('127.0.0.11', True, 'listed'),
    ('127.0.0.99', False, 'error'),
    ('127.1.2.3', False, 'error'),
])
def test_spamhaus_answers_validated_against_documented_codes(monkeypatch, answer,
                                                             expected_listed, expected_status):
    import asyncio

    class FakeAnswer:
        def __init__(self, ips): self._ips = ips
        def __iter__(self): return iter(self._ips)

    async def fake_resolve(query, rdtype='A', timeout=10):
        return FakeAnswer([answer])

    import app.services.dns_resolver as dnsr
    monkeypatch.setattr(dnsr, 'resolve_for_blacklist', fake_resolve)
    result = asyncio.run(blacklist_service.check_ip_in_blacklist(
        '203.0.113.5', {'name': 'Spamhaus ZEN', 'zone': 'zen.spamhaus.org', 'info_url': ''}, 0))
    assert result['listed'] is expected_listed
    assert result['status'] == expected_status


def test_non_spamhaus_zone_keeps_generic_127_semantics(monkeypatch):
    import asyncio

    class FakeAnswer:
        def __init__(self, ips): self._ips = ips
        def __iter__(self): return iter(self._ips)

    async def fake_resolve(query, rdtype='A', timeout=10):
        return FakeAnswer(['127.0.0.2'])

    import app.services.dns_resolver as dnsr
    monkeypatch.setattr(dnsr, 'resolve_for_blacklist', fake_resolve)
    result = asyncio.run(blacklist_service.check_ip_in_blacklist(
        '203.0.113.5', {'name': 'SpamCop', 'zone': 'bl.spamcop.net', 'info_url': ''}, 0))
    assert result['listed'] is True
