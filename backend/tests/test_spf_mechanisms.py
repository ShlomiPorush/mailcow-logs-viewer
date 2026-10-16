"""SPF syntax check: ptr and exp= are legal SPF (RFC 7208), not errors."""
import pytest

from app.config import settings
from app.routers import domains


class FakeTXT:
    def __init__(self, text):
        self.strings = (text.encode(),)


async def _check(monkeypatch, spf_text):
    async def fake_resolve(query, record_type='TXT', timeout=5):
        return [FakeTXT(spf_text)] if record_type == 'TXT' else []
    monkeypatch.setattr(domains, 'resolve_dns_with_fallback', fake_resolve)
    monkeypatch.setattr(settings._inner, 'domain_spf_source_dmarc_history', False)
    return await domains.check_spf_record('example.com', spf_source_ips=[])


@pytest.mark.asyncio
async def test_exp_modifier_is_valid_spf(monkeypatch):
    result = await _check(monkeypatch, 'v=spf1 mx exp=explain.example.com -all')
    assert result['status'] == 'success', result['message']
    assert 'Invalid' not in result['message']


@pytest.mark.parametrize('term', ['ptr', 'ptr:example.net', '?ptr'])
@pytest.mark.asyncio
async def test_ptr_is_a_warning_not_an_error(monkeypatch, term):
    result = await _check(monkeypatch, f'v=spf1 mx {term} -all')
    assert result['status'] == 'warning', result['message']
    assert 'Invalid' not in result['message']
    assert any('ptr' in w for w in result['warnings'])
    # ptr is a DNS lookup (RFC 7208 4.6.4): mx and ptr
    assert result['dns_lookups'] == 2


@pytest.mark.asyncio
async def test_unknown_mechanism_is_still_an_error(monkeypatch):
    result = await _check(monkeypatch, 'v=spf1 mx bogus:example.net -all')
    assert result['status'] == 'error'
    assert 'Invalid SPF mechanisms: bogus:example.net' in result['message']


@pytest.mark.asyncio
async def test_unknown_modifiers_are_ignored(monkeypatch):
    """RFC 7208 section 6: unknown modifiers (name=value) must be ignored.
    ra=, rp= and rr= are the SPF failure reporting modifiers of RFC 6652."""
    result = await _check(monkeypatch, 'v=spf1 mx ra=postmaster rp=10 rr=all -all')
    assert result['status'] == 'success', result['message']
    assert 'Invalid' not in result['message']
    # Only mx is a lookup; a modifier is never resolved
    assert result['dns_lookups'] == 1


@pytest.mark.parametrize('term', ['-foo=bar', '=bar', 'foo'])
@pytest.mark.asyncio
async def test_terms_that_are_no_modifier_are_still_errors(monkeypatch, term):
    """Modifiers take no qualifier and need a name: these are invalid terms."""
    result = await _check(monkeypatch, f'v=spf1 mx {term} -all')
    assert result['status'] == 'error'
    assert f'Invalid SPF mechanisms: {term}' in result['message']


@pytest.mark.asyncio
async def test_mechanism_written_as_a_modifier_is_a_warning(monkeypatch):
    """include=example.net is an unknown modifier, so SPF ignores it, but it
    is almost always a typo for include:example.net."""
    result = await _check(monkeypatch, 'v=spf1 mx include=example.net -all')
    assert result['status'] == 'warning', result['message']
    assert any('include=example.net' in w for w in result['warnings'])
    assert result['dns_lookups'] == 1


@pytest.mark.parametrize('term', ['abc', 'mxfoo', 'allx', 'ptrx', 'a:', 'include', 'ip4', '--all', '-redirect=example.net'])
@pytest.mark.asyncio
async def test_a_term_that_only_starts_like_a_mechanism_is_an_error(monkeypatch, term):
    """RFC 7208 sections 4.6.1 and 5: the mechanism name is matched whole, then
    only what that mechanism allows may follow (nothing, ':' or '/')."""
    result = await _check(monkeypatch, f'v=spf1 mx {term} -all')
    assert result['status'] == 'error', result['message']
    assert f'Invalid SPF mechanisms: {term}' in result['message']


@pytest.mark.parametrize('term', ['a', 'a:mail.example.com', 'a/24', 'a:mail.example.com/24//64', 'a//64',
                                  'mx/24', 'mx:example.net', 'ip4:192.0.2.0/24', 'ip4:192.0.2.1',
                                  'ip6:2001:db8::/32', 'ip6:2001:db8::1', '~include:example.com',
                                  '+exists:%{i}.example.net', '?all'])
@pytest.mark.asyncio
async def test_well_formed_mechanisms_stay_valid(monkeypatch, term):
    result = await _check(monkeypatch, f'v=spf1 {term} -all')
    assert 'Invalid' not in result['message'], result['message']


@pytest.mark.parametrize('term', ['MX', 'Include:example.com', 'IP4:192.0.2.0/24', 'A/24', 'Ptr', 'Redirect=example.net'])
@pytest.mark.asyncio
async def test_mechanism_names_are_case_insensitive(monkeypatch, term):
    """RFC 7208 section 4.6.1: mechanism and modifier names are case-insensitive."""
    result = await _check(monkeypatch, f'v=spf1 {term} -all')
    assert 'Invalid' not in result['message'], result['message']


@pytest.mark.asyncio
async def test_a_record_written_in_upper_case_is_checked_like_lower_case(monkeypatch):
    """V=SPF1 and -ALL too: the version and every name are case-insensitive
    (RFC 7208 section 12, ABNF strings per RFC 5234)."""
    result = await _check(monkeypatch, 'V=SPF1 MX -ALL')
    assert result['status'] == 'success', result['message']
    assert result['record'] == 'V=SPF1 MX -ALL'
    assert result['has_strict_all'] is True
    assert result['includes_mx'] is True
    assert result['dns_lookups'] == 1


class FakeAddr:
    def __init__(self, ip):
        self.ip = ip

    def __str__(self):
        return self.ip


class FakeMX:
    def __init__(self, exchange):
        self.exchange = exchange


def _fake_dns(monkeypatch, records):
    """records: {(name, type): [rdata, ...]}; anything else resolves to nothing."""
    async def fake_resolve(query, record_type='TXT', timeout=5):
        return records.get((query.lower(), record_type), [])
    monkeypatch.setattr(domains, 'resolve_dns_with_fallback', fake_resolve)


@pytest.mark.parametrize('record, lookups', [
    ('v=spf1 a/24 -all', 1),
    ('v=spf1 mx/24 -all', 1),
    ('v=spf1 a//64 mx//64 -all', 2),
    ('v=spf1 a:mail.example.com/24//64 mx:example.net//64 -all', 2),
    ('v=spf1 a/24 mx/24 a:mail.example.com/24//64 ip4:192.0.2.0/24 -all', 3),
])
@pytest.mark.asyncio
async def test_a_and_mx_with_a_cidr_length_are_dns_lookups(monkeypatch, record, lookups):
    """RFC 7208 section 4.6.4: every a and mx term is a DNS lookup, whatever its CIDR length."""
    _fake_dns(monkeypatch, {})
    assert await domains.count_spf_dns_lookups('example.com', record) == lookups


@pytest.mark.asyncio
async def test_upper_case_terms_are_counted_as_dns_lookups(monkeypatch):
    _fake_dns(monkeypatch, {('example.net', 'TXT'): [FakeTXT('V=SPF1 MX A -ALL')]})
    record = 'v=spf1 A MX/24 Include:example.net EXISTS:%{i}.example.org PTR Redirect=example.org'
    # A, MX/24, Include (+ its MX and A), EXISTS, PTR, Redirect
    assert await domains.count_spf_dns_lookups('example.com', record) == 8


_AUTH_DNS = {
    ('mail.example.com', 'A'): [FakeAddr('192.0.2.10')],
    ('example.com', 'A'): [FakeAddr('192.0.2.20')],
    ('example.com', 'MX'): [FakeMX('mx.example.com')],
    ('mx.example.com', 'A'): [FakeAddr('192.0.2.30')],
}


@pytest.mark.parametrize('lower, upper, ip, nested', [
    ('v=spf1 ip4:192.0.2.0/24 -all', 'V=SPF1 IP4:192.0.2.0/24 -ALL', '192.0.2.5', None),
    ('v=spf1 ip6:2001:db8::/32 -all', 'v=spf1 IP6:2001:DB8::/32 -all', '2001:db8::5', None),
    ('v=spf1 a:mail.example.com -all', 'v=spf1 A:mail.example.com -all', '192.0.2.10', None),
    ('v=spf1 a -all', 'v=spf1 A -all', '192.0.2.20', None),
    ('v=spf1 mx -all', 'v=spf1 MX -all', '192.0.2.30', None),
    ('v=spf1 include:example.net -all', 'v=spf1 Include:example.net -all', '198.51.100.7', 'v=spf1 ip4:198.51.100.0/24 -all'),
    ('v=spf1 include:example.net -all', 'v=spf1 include:example.net -all', '198.51.100.7', 'V=SPF1 IP4:198.51.100.0/24 -ALL'),
    ('v=spf1 redirect=example.net', 'v=spf1 REDIRECT=example.net', '198.51.100.7', 'v=spf1 ip4:198.51.100.0/24 -all'),
])
@pytest.mark.asyncio
async def test_an_upper_case_record_authorizes_like_lower_case(monkeypatch, lower, upper, ip, nested):
    dns = dict(_AUTH_DNS)
    if nested:
        dns[('example.net', 'TXT')] = [FakeTXT(nested)]
    _fake_dns(monkeypatch, dns)
    ok_lower, method_lower = await domains.check_ip_in_spf('example.com', ip, lower)
    ok_upper, method_upper = await domains.check_ip_in_spf('example.com', ip, upper)
    assert ok_lower is True, method_lower
    assert ok_upper is True, method_upper
    assert method_upper.lower() == method_lower.lower()
