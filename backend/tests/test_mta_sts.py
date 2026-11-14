"""MTA-STS checks (RFC 8461): the _mta-sts TXT record, the policy file behind
it, and whether the domain's MX hosts are covered. DNS and HTTPS are injected;
no live lookups (the repository's rule for network-facing code)."""
import asyncio
import gzip
import time

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

import dns.resolver
import httpx

from app.routers import domains


class FakeTXT:
    def __init__(self, text):
        self.strings = [text.encode()]


class FakeMX:
    def __init__(self, exchange):
        self.exchange = exchange


def _dns(records):
    """records: {(name, rtype): [rdata] | Exception}"""
    async def resolve(name, rtype, timeout=5):
        value = records.get((name, rtype))
        if value is None:
            raise dns.resolver.NXDOMAIN()
        if isinstance(value, Exception):
            raise value
        return value
    return resolve


def _policy(text_or_exc):
    async def fetch(domain):
        if isinstance(text_or_exc, Exception):
            raise text_or_exc
        return text_or_exc
    return fetch


def _check(monkeypatch, records, policy=None):
    monkeypatch.setattr(domains, 'resolve_dns_with_fallback', _dns(records))
    if policy is not None:
        monkeypatch.setattr(domains, '_fetch_mta_sts_policy', _policy(policy))
    return asyncio.run(domains.check_mta_sts_record('example.test'))


GOOD_POLICY = "version: STSv1\nmode: enforce\nmx: mail.example.test\nmax_age: 604800\n"


def test_missing_record_is_a_warning_not_an_error(monkeypatch):
    """MTA-STS is optional, like TLSA. The message must contain 'not published'
    so detect_dns_changes treats a later removal as definitive."""
    result = _check(monkeypatch, {})
    assert result['status'] == 'warning'
    assert 'not published' in result['message']


def test_enforced_policy_with_covered_mx_is_success(monkeypatch):
    result = _check(monkeypatch, {
        ('_mta-sts.example.test', 'TXT'): [FakeTXT('v=STSv1; id=20260911T000000;')],
        ('example.test', 'MX'): [FakeMX('mail.example.test.')],
    }, policy=GOOD_POLICY)
    assert result['status'] == 'success'
    assert result['record'] == 'v=STSv1; id=20260911T000000;'
    assert any('enforce' in i.lower() for i in result['info'])


def test_wildcard_mx_pattern_matches_one_label(monkeypatch):
    result = _check(monkeypatch, {
        ('_mta-sts.example.test', 'TXT'): [FakeTXT('v=STSv1; id=1;')],
        ('example.test', 'MX'): [FakeMX('mx1.example.test.')],
    }, policy="version: STSv1\nmode: enforce\nmx: *.example.test\nmax_age: 86400\n")
    assert result['status'] == 'success'


def test_testing_mode_is_a_warning(monkeypatch):
    result = _check(monkeypatch, {
        ('_mta-sts.example.test', 'TXT'): [FakeTXT('v=STSv1; id=1;')],
        ('example.test', 'MX'): [FakeMX('mail.example.test.')],
    }, policy="version: STSv1\nmode: testing\nmx: mail.example.test\nmax_age: 86400\n")
    assert result['status'] == 'warning'
    assert 'testing' in result['message']


def test_record_with_unreachable_policy_is_an_error(monkeypatch):
    """A published record with a broken policy is worse than no record:
    senders that enforce MTA-STS treat it as a hard failure."""
    result = _check(monkeypatch, {
        ('_mta-sts.example.test', 'TXT'): [FakeTXT('v=STSv1; id=1;')],
    }, policy=ConnectionError('connection refused'))
    assert result['status'] == 'error'
    assert 'could not be fetched' in result['message']


def test_multiple_sts_records_are_an_error(monkeypatch):
    result = _check(monkeypatch, {
        ('_mta-sts.example.test', 'TXT'): [FakeTXT('v=STSv1; id=1;'), FakeTXT('v=STSv1; id=2;')],
    })
    assert result['status'] == 'error'


def test_uncovered_mx_under_enforce_is_an_error(monkeypatch):
    result = _check(monkeypatch, {
        ('_mta-sts.example.test', 'TXT'): [FakeTXT('v=STSv1; id=1;')],
        ('example.test', 'MX'): [FakeMX('mail.other.invalid.')],
    }, policy=GOOD_POLICY)
    assert result['status'] == 'error'
    assert 'mail.other.invalid' in result['message']


def test_dns_failure_is_unknown_and_never_counts_as_removal(monkeypatch):
    """A resolver failure must not read as 'the record is gone', or a DNS
    hiccup would fire a change alert."""
    result = _check(monkeypatch, {
        ('_mta-sts.example.test', 'TXT'): dns.resolver.LifetimeTimeout(),
    })
    assert result['status'] == 'unknown'
    assert not domains._definitely_absent(result)


def test_change_detection_fires_on_id_change_only(monkeypatch):
    """The whole point of the id field: it changes when the policy changes."""
    class Prev:
        spf_check = None
        dkim_check = None
        dmarc_check = None
        tlsa_check = None
        mta_sts_check = {'status': 'success', 'record': 'v=STSv1; id=OLD;'}

    changed = domains.detect_dns_changes(Prev(), {
        'mta_sts': {'status': 'success', 'record': 'v=STSv1; id=NEW;'}})
    assert changed == [{'type': 'MTA-STS', 'old': 'v=STSv1; id=OLD;', 'new': 'v=STSv1; id=NEW;'}]

    unchanged = domains.detect_dns_changes(Prev(), {
        'mta_sts': {'status': 'success', 'record': 'v=STSv1; id=OLD;'}})
    assert unchanged == []

    # a failed lookup (record None, no absence keywords) is not a removal
    hiccup = domains.detect_dns_changes(Prev(), {
        'mta_sts': {'status': 'unknown', 'message': 'MTA-STS check failed: timeout', 'record': None}})
    assert hiccup == []

    # a definitive absence is a removal
    removed = domains.detect_dns_changes(Prev(), {
        'mta_sts': {'status': 'warning', 'message': 'MTA-STS record not published', 'record': None}})
    assert removed == [{'type': 'MTA-STS', 'old': 'v=STSv1; id=OLD;', 'new': '(removed)'}]


def test_policy_parser_handles_crlf_and_junk():
    policy = domains._parse_mta_sts_policy(
        "version: STSv1\r\nmode: enforce\r\nmx: a.example.test\r\nmx: *.b.example.test\r\nmax_age: 60\r\n\r\nnonsense line\n")
    assert policy['version'] == 'STSv1'
    assert policy['mode'] == 'enforce'
    assert policy['mx'] == ['a.example.test', '*.b.example.test']
    assert policy['max_age'] == '60'


# --- the policy fetch itself ----------------------------------------------------
# The policy host belongs to the domain's owner, so what it sends is untrusted:
# a compressed body expands to whatever size it likes, and a slow one keeps the
# check (and the background DNS job) waiting. The fetch runs against an
# in-memory transport; nothing leaves the process.


class FakeBody(httpx.AsyncByteStream):
    """A response body that records how much of it the client read."""

    def __init__(self, chunks, gap=0.0):
        self.chunks = chunks
        self.gap = gap
        self.sent = 0
        self.closed = False

    async def __aiter__(self):
        for chunk in self.chunks:
            if self.gap:
                await asyncio.sleep(self.gap)
            self.sent += len(chunk)
            yield chunk

    async def aclose(self):
        self.closed = True


def _policy_host(monkeypatch, body, headers=None):
    """Serve body for every request and return the requests seen."""
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, headers=headers or {}, stream=body)

    real_client = httpx.AsyncClient

    class Client(real_client):
        def __init__(self, *args, **kwargs):
            kwargs['transport'] = httpx.MockTransport(handler)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx, 'AsyncClient', Client)
    return requests


def test_compressed_policy_is_refused_without_reading_it(monkeypatch):
    bomb = gzip.compress(b'\0' * (4 * 1024 * 1024))
    body = FakeBody([bomb])
    _policy_host(monkeypatch, body, {'Content-Encoding': 'gzip'})
    with pytest.raises(ValueError, match='compressed'):
        asyncio.run(domains._fetch_mta_sts_policy('example.test'))
    assert body.sent == 0
    assert body.closed


def test_compressed_policy_makes_the_check_an_error(monkeypatch):
    monkeypatch.setattr(domains, 'resolve_dns_with_fallback', _dns({
        ('_mta-sts.example.test', 'TXT'): [FakeTXT('v=STSv1; id=1;')]}))
    _policy_host(monkeypatch, FakeBody([gzip.compress(GOOD_POLICY.encode())]),
                 {'Content-Encoding': 'gzip'})
    result = asyncio.run(domains.check_mta_sts_record('example.test'))
    assert result['status'] == 'error'
    assert 'could not be fetched' in result['message']


def test_policy_over_the_cap_stops_reading_at_the_cap(monkeypatch):
    # No Content-Length, so only counting the bytes read can stop it
    chunk = b'#' * 16384
    body = FakeBody([chunk] * 100)
    _policy_host(monkeypatch, body)
    with pytest.raises(ValueError, match='larger than expected'):
        asyncio.run(domains._fetch_mta_sts_policy('example.test'))
    assert body.sent <= domains.MTA_STS_POLICY_MAX_BYTES + len(chunk)
    assert body.closed


def test_declared_length_over_the_cap_is_refused_before_reading(monkeypatch):
    body = FakeBody([b'#' * 16384] * 100)
    _policy_host(monkeypatch, body, {'Content-Length': str(16384 * 100)})
    with pytest.raises(ValueError, match='larger than expected'):
        asyncio.run(domains._fetch_mta_sts_policy('example.test'))
    assert body.sent == 0


def test_slow_policy_is_cut_by_one_deadline(monkeypatch):
    # Every gap is far below the per-read timeout; only a total deadline ends it
    monkeypatch.setattr(domains, 'MTA_STS_POLICY_TIMEOUT', 0.5)
    body = FakeBody([b'version: STSv1\n'] + [b'\n'] * 100, gap=0.05)
    _policy_host(monkeypatch, body)
    started = time.monotonic()
    with pytest.raises(ValueError, match='too long'):
        asyncio.run(domains._fetch_mta_sts_policy('example.test'))
    assert time.monotonic() - started < 2
    assert body.sent < 100


def test_valid_policy_is_fetched_uncompressed_and_parsed(monkeypatch):
    monkeypatch.setattr(domains, 'resolve_dns_with_fallback', _dns({
        ('_mta-sts.example.test', 'TXT'): [FakeTXT('v=STSv1; id=1;')],
        ('example.test', 'MX'): [FakeMX('mail.example.test.')],
    }))
    requests = _policy_host(monkeypatch, FakeBody([GOOD_POLICY[:20].encode(), GOOD_POLICY[20:].encode()]),
                            {'Content-Type': 'text/plain'})
    result = asyncio.run(domains.check_mta_sts_record('example.test'))
    assert result['status'] == 'success'
    assert [str(r.url) for r in requests] == ['https://mta-sts.example.test/.well-known/mta-sts.txt']
    assert requests[0].headers['Accept-Encoding'] == 'identity'
