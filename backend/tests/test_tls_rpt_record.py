"""TLS-RPT record checks (RFC 8460): the _smtp._tls TXT record that tells
sending servers where to deliver TLS reports. DNS is injected; no live
lookups (the repository's rule for network-facing code)."""
import asyncio

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

import dns.resolver

from app.routers import domains

from test_mta_sts import FakeTXT, _dns

NAME = '_smtp._tls.example.test'


def _check(monkeypatch, records):
    monkeypatch.setattr(domains, 'resolve_dns_with_fallback', _dns(records))
    return asyncio.run(domains.check_tls_rpt_record('example.test'))


def test_valid_record_is_success_and_lists_report_addresses(monkeypatch):
    result = _check(monkeypatch, {(NAME, 'TXT'): [
        FakeTXT('v=TLSRPTv1; rua=mailto:tls@example.test,https://reports.example.test/tls'),
    ]})
    assert result['status'] == 'success'
    assert result['record'] == 'v=TLSRPTv1; rua=mailto:tls@example.test,https://reports.example.test/tls'
    assert result['report_uris'] == ['mailto:tls@example.test', 'https://reports.example.test/tls']
    assert result['warnings'] == []


def test_missing_record_is_a_warning_not_an_error(monkeypatch):
    """TLS-RPT is optional. The message must contain 'not published' so
    detect_dns_changes treats a later removal as definitive."""
    result = _check(monkeypatch, {})
    assert result['status'] == 'warning'
    assert 'not published' in result['message']
    assert domains._definitely_absent(result)


def test_other_txt_records_at_the_name_are_ignored(monkeypatch):
    result = _check(monkeypatch, {(NAME, 'TXT'): [FakeTXT('google-site-verification=abc')]})
    assert result['status'] == 'warning'
    assert 'not published' in result['message']


def test_multiple_records_are_an_error(monkeypatch):
    result = _check(monkeypatch, {(NAME, 'TXT'): [
        FakeTXT('v=TLSRPTv1; rua=mailto:a@example.test'),
        FakeTXT('v=TLSRPTv1; rua=mailto:b@example.test'),
    ]})
    assert result['status'] == 'error'
    assert result['report_uris'] == []


@pytest.mark.parametrize('record', ['v=TLSRPTv1;', 'v=TLSRPTv1; rua=', 'v=TLSRPTv1; rua=ftp://example.test/x'])
def test_record_without_a_usable_rua_is_an_error(monkeypatch, record):
    result = _check(monkeypatch, {(NAME, 'TXT'): [FakeTXT(record)]})
    assert result['status'] == 'error'
    assert result['record'] == record


def test_unsupported_address_next_to_a_valid_one_is_a_warning(monkeypatch):
    result = _check(monkeypatch, {(NAME, 'TXT'): [
        FakeTXT('v=TLSRPTv1; rua=mailto:tls@example.test,ftp://example.test/x'),
    ]})
    assert result['status'] == 'success'
    assert result['report_uris'] == ['mailto:tls@example.test']
    assert len(result['warnings']) == 1 and 'ftp://example.test/x' in result['warnings'][0]


def test_version_tag_is_case_insensitive_and_needs_the_exact_version(monkeypatch):
    assert _check(monkeypatch, {(NAME, 'TXT'): [FakeTXT('v=tlsrptv1;rua=mailto:tls@example.test')]})['status'] == 'success'
    assert _check(monkeypatch, {(NAME, 'TXT'): [FakeTXT('v=TLSRPTv10; rua=mailto:tls@example.test')]})['status'] == 'warning'


def test_dns_failure_is_unknown_and_never_counts_as_removal(monkeypatch):
    result = _check(monkeypatch, {(NAME, 'TXT'): dns.resolver.LifetimeTimeout()})
    assert result['status'] == 'unknown'
    assert not domains._definitely_absent(result)


class Prev:
    spf_check = None
    dkim_check = None
    dmarc_check = None
    tlsa_check = None
    mta_sts_check = None
    tls_rpt_check = {'status': 'success', 'record': 'v=TLSRPTv1; rua=mailto:old@example.test'}


def test_change_detection_fires_on_record_change_and_removal():
    changed = domains.detect_dns_changes(Prev(), {
        'tls_rpt': {'status': 'success', 'record': 'v=TLSRPTv1; rua=mailto:new@example.test'}})
    assert changed == [{'type': 'TLS-RPT', 'old': 'v=TLSRPTv1; rua=mailto:old@example.test',
                        'new': 'v=TLSRPTv1; rua=mailto:new@example.test'}]

    hiccup = domains.detect_dns_changes(Prev(), {
        'tls_rpt': {'status': 'unknown', 'message': 'Could not check TLS-RPT record.', 'record': None}})
    assert hiccup == []

    removed = domains.detect_dns_changes(Prev(), {
        'tls_rpt': {'status': 'warning', 'message': 'TLS-RPT record not published', 'record': None}})
    assert removed == [{'type': 'TLS-RPT', 'old': 'v=TLSRPTv1; rua=mailto:old@example.test', 'new': '(removed)'}]


def test_first_check_after_upgrade_does_not_alert():
    """Rows stored before this check existed have no TLS-RPT result. Finding a
    record on the first check after upgrading is not a change."""
    class Upgraded(Prev):
        tls_rpt_check = None

    assert domains.detect_dns_changes(Upgraded(), {
        'tls_rpt': {'status': 'success', 'record': 'v=TLSRPTv1; rua=mailto:tls@example.test'}}) == []
