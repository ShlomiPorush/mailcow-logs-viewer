"""MTA-STS checks (RFC 8461): the _mta-sts TXT record, the policy file behind
it, and whether the domain's MX hosts are covered. DNS and HTTPS are injected;
no live lookups (the repository's rule for network-facing code)."""
import asyncio

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

import dns.resolver

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
