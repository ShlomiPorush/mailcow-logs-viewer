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
