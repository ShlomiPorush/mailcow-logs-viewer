"""
Tests for tolerant DKIM record matching (issue #292).

DNS providers rewrite DKIM records: they reorder tags, add h=sha256, drop
t=s or fold the key. Only differences that stop receivers from verifying
mailcow's signatures may be reported as a mismatch.
"""
import pytest

from app.routers import domains

KEY = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtestkeyonly' + 'A' * 40 + 'IDAQAB'
OTHER_KEY = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAotherkey' + 'B' * 40 + 'IDAQAB'
MAILCOW_RECORD = f'v=DKIM1;k=rsa;t=s;s=email;p={KEY}'


class FakeTXT:
    """Mimics a dnspython TXT rdata that may be split into several strings."""
    def __init__(self, *parts):
        self.strings = tuple(part.encode() for part in parts)


async def _check(monkeypatch, *txt_parts, mailcow_record=MAILCOW_RECORD):
    async def fake_get_dkim(domain):
        return {'dkim_selector': 'dkim', 'dkim_txt': mailcow_record}

    async def fake_resolve(name, record_type, timeout=5):
        assert name == 'dkim._domainkey.example.com'
        return [FakeTXT(*txt_parts)]

    monkeypatch.setattr(domains.mailcow_api, 'get_dkim', fake_get_dkim)
    monkeypatch.setattr(domains, 'resolve_dns_with_fallback', fake_resolve)
    return await domains.check_dkim_record('example.com')


@pytest.mark.asyncio
async def test_provider_rewritten_record_is_not_a_mismatch(monkeypatch):
    # Shape reported in #292: reordered, h=sha256 added, t=s dropped,
    # trailing semicolon, key split across two TXT strings
    published = f'v=DKIM1; h=sha256; k=rsa; p={KEY}; s=email;'
    result = await _check(monkeypatch, published[:120], published[120:])

    assert result['match'] is True
    assert result['status'] == 'warning'
    assert result['message'] != 'DKIM record mismatch'
    assert any('t=s from the mailcow record is missing' in w for w in result['warnings'])
    assert any('h=sha256 is not in the mailcow record' in w for w in result['warnings'])


@pytest.mark.asyncio
async def test_identical_tags_in_any_order_are_success(monkeypatch):
    result = await _check(monkeypatch, f'v=DKIM1; p={KEY}; s=email; t=s; k=rsa')

    assert result['match'] is True
    assert result['status'] == 'success'
    assert result['warnings'] == []


@pytest.mark.asyncio
async def test_whitespace_inside_key_is_ignored(monkeypatch):
    folded = KEY[:30] + ' ' + KEY[30:60] + '\t' + KEY[60:]
    result = await _check(monkeypatch, f'v=DKIM1;k=rsa;t=s;s=email;p={folded}')

    assert result['match'] is True
    assert result['status'] == 'success'


@pytest.mark.asyncio
async def test_different_key_is_a_mismatch(monkeypatch):
    result = await _check(monkeypatch, f'v=DKIM1;k=rsa;t=s;s=email;p={OTHER_KEY}')

    assert result['match'] is False
    assert result['status'] == 'error'
    assert result['message'] == 'DKIM record mismatch'
    assert any('Public key (p=)' in w for w in result['warnings'])


@pytest.mark.asyncio
async def test_different_key_type_is_a_mismatch(monkeypatch):
    result = await _check(monkeypatch, f'v=DKIM1;k=ed25519;t=s;s=email;p={KEY}')

    assert result['match'] is False
    assert result['message'] == 'DKIM record mismatch'


@pytest.mark.asyncio
async def test_missing_key_type_defaults_to_rsa(monkeypatch):
    result = await _check(monkeypatch, f'v=DKIM1;t=s;s=email;p={KEY}')

    assert result['match'] is True
    assert result['status'] == 'success'


@pytest.mark.asyncio
async def test_hash_list_without_sha256_is_a_mismatch(monkeypatch):
    result = await _check(monkeypatch, f'v=DKIM1;h=sha1;k=rsa;t=s;s=email;p={KEY}')

    assert result['match'] is False
    assert result['message'] == 'DKIM record mismatch'
    assert not any('is not in the mailcow record' in w for w in result['warnings'])


@pytest.mark.asyncio
async def test_hash_list_including_sha256_matches(monkeypatch):
    result = await _check(monkeypatch, f'v=DKIM1;h=sha1:sha256;k=rsa;t=s;s=email;p={KEY}')

    assert result['match'] is True


@pytest.mark.asyncio
async def test_revoked_key_is_still_reported(monkeypatch):
    result = await _check(monkeypatch, 'v=DKIM1;k=rsa;t=s;s=email;p=')

    assert result['match'] is False
    assert result['status'] == 'error'
