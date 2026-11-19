"""The DMARC check reads the policy from the p tag: a search of the record for
"p=" also finds sp=, the subdomain policy, and reported the wrong one."""
import pytest

from app.routers import domains


class FakeTXT:
    def __init__(self, text):
        self.strings = (text.encode(),)


async def _check(monkeypatch, record):
    async def fake_resolve(query, record_type='TXT', timeout=5):
        return [FakeTXT(record)]
    monkeypatch.setattr(domains, 'resolve_dns_with_fallback', fake_resolve)
    return await domains.check_dmarc_record('example.com')


@pytest.mark.parametrize('record, policy, strong', [
    ('v=DMARC1; sp=reject; p=none; rua=mailto:d@example.com', 'none', False),
    ('v=DMARC1; p=quarantine; sp=none', 'quarantine', True),
    ('v=DMARC1; p=Reject', 'reject', True),
    ('v=DMARC1; sp=reject', 'unknown', False),
    ('v=DMARC1; p=block', 'unknown', False),
])
@pytest.mark.asyncio
async def test_the_policy_is_the_p_tag(monkeypatch, record, policy, strong):
    result = await _check(monkeypatch, record)
    assert result['policy'] == policy
    assert result['is_strong'] is strong
    assert result['status'] == ('success' if strong else 'warning')
