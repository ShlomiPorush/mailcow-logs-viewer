"""DoH fallback of the shared resolver (issue #360): a SERVFAIL is a failed
lookup, not a missing record. Reporting it as NoAnswer made the Domains page
say "No TXT records found" for a domain whose DNSSEC validation failed.
UDP and DoH are injected; no live lookups."""
import asyncio

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

import dns.asyncquery
import dns.asyncresolver
import dns.message
import dns.name
import dns.rcode
import dns.resolver
import dns.rrset

from app.routers import domains
from app.services import dns_resolver

DOMAIN = 'example.test'


def _udp_blocked(monkeypatch):
    async def fail(self, *args, **kwargs):
        raise dns.resolver.NoNameservers()
    monkeypatch.setattr(dns.asyncresolver.Resolver, 'resolve', fail)


def _doh_answers(monkeypatch, rcode, answer=None):
    async def https(q, url, timeout=None):
        response = dns.message.make_response(q)
        response.set_rcode(rcode)
        if answer:
            response.answer.append(answer)
        # The real https() parses the answer off the wire
        return dns.message.from_wire(response.to_wire())
    monkeypatch.setattr(dns.asyncquery, 'https', https)


def test_doh_servfail_is_a_failure_not_a_missing_record(monkeypatch):
    _udp_blocked(monkeypatch)
    _doh_answers(monkeypatch, dns.rcode.SERVFAIL)

    with pytest.raises(Exception) as excinfo:
        asyncio.run(dns_resolver.resolve(DOMAIN, 'TXT'))

    assert not isinstance(excinfo.value, dns.resolver.NoAnswer)
    assert 'SERVFAIL' in str(excinfo.value)


def test_doh_empty_noerror_is_still_no_answer(monkeypatch):
    _udp_blocked(monkeypatch)
    _doh_answers(monkeypatch, dns.rcode.NOERROR)

    with pytest.raises(dns.resolver.NoAnswer):
        asyncio.run(dns_resolver.resolve(DOMAIN, 'TXT'))


def test_doh_nxdomain_is_still_nxdomain(monkeypatch):
    _udp_blocked(monkeypatch)
    _doh_answers(monkeypatch, dns.rcode.NXDOMAIN)

    with pytest.raises(dns.resolver.NXDOMAIN):
        asyncio.run(dns_resolver.resolve(DOMAIN, 'TXT'))


def test_doh_answer_is_returned(monkeypatch):
    _udp_blocked(monkeypatch)
    record = dns.rrset.from_text(dns.name.from_text(DOMAIN), 300, 'IN', 'TXT', '"v=spf1 mx -all"')
    _doh_answers(monkeypatch, dns.rcode.NOERROR, record)

    answer = asyncio.run(dns_resolver.resolve(DOMAIN, 'TXT'))

    assert [r.to_text() for r in answer] == ['"v=spf1 mx -all"']


def test_spf_card_does_not_claim_missing_records_on_servfail(monkeypatch):
    _udp_blocked(monkeypatch)
    _doh_answers(monkeypatch, dns.rcode.SERVFAIL)

    result = asyncio.run(domains.check_spf_record(DOMAIN, spf_source_ips=[]))

    assert result['status'] == 'error'
    assert result['message'] != 'No TXT records found'


def test_dmarc_card_does_not_claim_missing_record_on_servfail(monkeypatch):
    _udp_blocked(monkeypatch)
    _doh_answers(monkeypatch, dns.rcode.SERVFAIL)

    result = asyncio.run(domains.check_dmarc_record(DOMAIN))

    assert result['message'] != 'No DMARC record configured'
