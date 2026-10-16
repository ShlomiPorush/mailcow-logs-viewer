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
