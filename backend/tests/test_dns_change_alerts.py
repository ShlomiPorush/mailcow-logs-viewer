import asyncio
from types import SimpleNamespace

import dns.rcode
import dns.resolver
import pytest

from app.routers import domains

DOMAIN = 'example.test'
MX = 'mx.example.test'
KEY = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A'

PUBLISHED = {
    'spf': 'v=spf1 mx -all',
    'dkim': f'v=DKIM1; k=rsa; p={KEY}',
    'dmarc': 'v=DMARC1; p=reject',
    'mta_sts': 'v=STSv1; id=20261125;',
    'tls_rpt': 'v=TLSRPTv1; rua=mailto:tls@example.test',
}
CHECKS = {
    'spf': domains.check_spf_record,
    'dkim': domains.check_dkim_record,
    'dmarc': domains.check_dmarc_record,
    'mta_sts': domains.check_mta_sts_record,
    'tls_rpt': domains.check_tls_rpt_record,
}
LABELS = {'spf': 'SPF', 'dkim': 'DKIM', 'dmarc': 'DMARC', 'mta_sts': 'MTA-STS', 'tls_rpt': 'TLS-RPT'}


def _txt(*values):
    return [SimpleNamespace(strings=(value.encode(),)) for value in values]


def _stored(**checks):
    columns = {f'{key}_check': None for key in ('spf', 'dkim', 'dmarc', 'dnssec', 'tlsa', 'mta_sts', 'tls_rpt')}
    columns.update({f'{key}_check': check for key, check in checks.items()})
    return SimpleNamespace(**columns)


def _answer(monkeypatch, answer):
    async def resolve(name, record_type='TXT', timeout=5):
        if isinstance(answer, Exception):
            raise answer
        return answer

    async def get_dkim(domain):
        return {'dkim_selector': 'dkim', 'dkim_txt': PUBLISHED['dkim']}

    async def policy(domain):
        raise TimeoutError

    async def no_spf_sources(*args, **kwargs):
        return []

    monkeypatch.setattr(domains, 'resolve_dns_with_fallback', resolve)
    monkeypatch.setattr(domains.mailcow_api, 'get_dkim', get_dkim)
    monkeypatch.setattr(domains, '_fetch_mta_sts_policy', policy)
    monkeypatch.setattr(domains, 'get_spf_source_ips', no_spf_sources)


def _run(monkeypatch, key, answer):
    _answer(monkeypatch, answer)
    return asyncio.run(CHECKS[key](DOMAIN))


@pytest.mark.parametrize('answer', [dns.resolver.NXDOMAIN(), dns.resolver.NoAnswer()], ids=['nxdomain', 'no-answer'])
@pytest.mark.parametrize('key', sorted(CHECKS))
def test_a_record_dns_says_is_gone_alerts_as_removed(monkeypatch, key, answer):
    before = _run(monkeypatch, key, _txt(PUBLISHED[key]))
    after = _run(monkeypatch, key, answer)
    assert domains.detect_dns_changes(_stored(**{key: before}), {key: after}) == [
        {'type': LABELS[key], 'old': PUBLISHED[key], 'new': '(removed)'}]


@pytest.mark.parametrize('key', ['spf', 'dmarc', 'mta_sts', 'tls_rpt'])
def test_other_txt_values_alone_alert_as_removed(monkeypatch, key):
    before = _run(monkeypatch, key, _txt(PUBLISHED[key]))
    after = _run(monkeypatch, key, _txt('unrelated=value'))
    assert [c['new'] for c in domains.detect_dns_changes(_stored(**{key: before}), {key: after})] == ['(removed)']


@pytest.mark.parametrize('key', sorted(CHECKS))
def test_a_record_that_appears_alerts(monkeypatch, key):
    before = _run(monkeypatch, key, dns.resolver.NoAnswer())
    after = _run(monkeypatch, key, _txt(PUBLISHED[key]))
    assert domains.detect_dns_changes(_stored(**{key: before}), {key: after}) == [
        {'type': LABELS[key], 'old': '(none)', 'new': PUBLISHED[key]}]


@pytest.mark.parametrize('key', sorted(CHECKS))
def test_a_failed_lookup_never_alerts(monkeypatch, key):
    present = _run(monkeypatch, key, _txt(PUBLISHED[key]))
    absent = _run(monkeypatch, key, dns.resolver.NoAnswer())
    failed = _run(monkeypatch, key, Exception('All DNS resolvers failed'))
    for before, after in ((present, failed), (absent, failed), (failed, present), (failed, absent)):
        assert domains.detect_dns_changes(_stored(**{key: before}), {key: after}) == []


def test_a_dkim_key_change_alerts(monkeypatch):
    before = _run(monkeypatch, 'dkim', _txt(PUBLISHED['dkim']))
    changed = PUBLISHED['dkim'].replace(KEY, KEY[::-1])
    after = _run(monkeypatch, 'dkim', _txt(changed))
    assert domains.detect_dns_changes(_stored(dkim=before), {'dkim': after}) == [
        {'type': 'DKIM', 'old': PUBLISHED['dkim'], 'new': changed}]


def test_the_order_of_two_dkim_values_is_no_change_and_a_change_of_either_is(monkeypatch):
    other = PUBLISHED['dkim'].replace(KEY, KEY[::-1])
    before = _run(monkeypatch, 'dkim', _txt(PUBLISHED['dkim'], other))
    turned = _run(monkeypatch, 'dkim', _txt(other, PUBLISHED['dkim']))
    assert domains.detect_dns_changes(_stored(dkim=before), {'dkim': turned}) == []
    one_left = _run(monkeypatch, 'dkim', _txt(PUBLISHED['dkim']))
    assert [c['type'] for c in domains.detect_dns_changes(_stored(dkim=before), {'dkim': one_left})] == ['DKIM']


def test_a_second_dkim_value_that_is_not_text_does_not_fail_the_check(monkeypatch):
    broken = SimpleNamespace(strings=(b'\xff\x00\xfe',))
    check = _run(monkeypatch, 'dkim', _txt(PUBLISHED['dkim']) + [broken])
    assert check['match'] is True
    assert '\x00' not in check['published']


def test_a_first_dkim_value_with_nul_can_be_stored(monkeypatch):
    check = _run(monkeypatch, 'dkim', _txt('\x00' + PUBLISHED['dkim']))
    assert '\x00' not in str(check) and check['actual_record'] == PUBLISHED['dkim']


def test_an_empty_dkim_value_alerts_as_removed(monkeypatch):
    before = _run(monkeypatch, 'dkim', _txt(PUBLISHED['dkim']))
    after = _run(monkeypatch, 'dkim', _txt(''))
    assert [c['new'] for c in domains.detect_dns_changes(_stored(dkim=before), {'dkim': after})] == ['(removed)']


def test_dkim_not_set_up_in_mailcow_never_alerts(monkeypatch):
    before = _run(monkeypatch, 'dkim', _txt(PUBLISHED['dkim']))

    async def no_key(domain):
        return None
    monkeypatch.setattr(domains.mailcow_api, 'get_dkim', no_key)
    after = asyncio.run(domains.check_dkim_record(DOMAIN))
    assert domains.detect_dns_changes(_stored(dkim=before), {'dkim': after}) == []


def test_checks_stored_by_2x_give_no_alert_after_the_upgrade(monkeypatch):
    stored = _stored(
        spf={'status': 'success', 'message': 'SPF configured correctly', 'record': PUBLISHED['spf']},
        dkim={'status': 'success', 'message': 'DKIM configured correctly', 'actual_record': PUBLISHED['dkim'],
              'expected_record': PUBLISHED['dkim'], 'match': True},
        dmarc={'status': 'error', 'message': 'No DMARC record configured', 'record': None},
        mta_sts={'status': 'warning', 'message': 'MTA-STS record not published', 'record': None})
    changed_key = PUBLISHED['dkim'].replace(KEY, KEY[::-1])
    now = {key: _run(monkeypatch, key, _txt(value)) for key, value in PUBLISHED.items()}
    now['dkim'] = _run(monkeypatch, 'dkim', _txt(changed_key))
    assert domains.detect_dns_changes(stored, now) == []
    removed = _run(monkeypatch, 'spf', dns.resolver.NoAnswer())
    assert [c['new'] for c in domains.detect_dns_changes(stored, {'spf': removed})] == ['(removed)']


def _tlsa(monkeypatch, records, mx_hosts=(MX,)):
    async def dnssec(name, record_type='A', timeout=5, checking_disabled=False):
        if record_type == 'MX':
            found = [SimpleNamespace(exchange=f'{host}.', preference=10) for host in mx_hosts]
        else:
            found = records if record_type == 'TLSA' else []
        return SimpleNamespace(rcode=dns.rcode.NOERROR, authenticated=True, records=found)

    async def unreachable(host):
        raise OSError

    monkeypatch.setattr(domains, 'resolve_dnssec_with_fallback', dnssec)
    monkeypatch.setattr(domains, '_fetch_mx_certificate', unreachable)
    return asyncio.run(domains.check_tlsa_record(DOMAIN))


def test_tlsa_records_that_are_gone_alert_unless_some_mail_servers_were_not_checked(monkeypatch):
    record = SimpleNamespace(usage=3, selector=1, mtype=1, cert=b'\xaa')
    before = _tlsa(monkeypatch, [record])
    gone = _tlsa(monkeypatch, [])
    assert [c['new'] for c in domains.detect_dns_changes(_stored(tlsa=before), {'tlsa': gone})] == ['(removed)']
    many = [f'mx{i}.example.test' for i in range(domains.MAX_DANE_MX_HOSTS + 1)]
    partly = _tlsa(monkeypatch, [], mx_hosts=many)
    assert domains.detect_dns_changes(_stored(tlsa=before), {'tlsa': partly}) == []
