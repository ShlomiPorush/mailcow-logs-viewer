"""DNSSEC and DANE checks (issue #287): DNSSEC validation of the domain, and
whether published TLSA records are validated and match the certificate the MX
presents. DNS and the port 25 probe are injected; no live lookups (the
repository's rule for network-facing code)."""
import asyncio
import datetime
import hashlib
from types import SimpleNamespace

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

import dns.flags
import dns.message
import dns.rcode
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.routers import domains
from app.services import dane, dns_resolver
from app.services.dns_resolver import DnssecAnswer

MX = 'mail.example.test'


def _certificate():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, MX)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


CERT = _certificate()
OTHER_CERT = _certificate()


def _spki_sha256(cert_der):
    spki = x509.load_der_x509_certificate(cert_der).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(spki).digest()


def ok(records=(), ad=True):
    return DnssecAnswer(dns.rcode.NOERROR, ad, list(records))


NX = DnssecAnswer(dns.rcode.NXDOMAIN, True, [])
SERVFAIL = DnssecAnswer(dns.rcode.SERVFAIL, False, [])


def mx(host=MX):
    return SimpleNamespace(exchange=host + '.')


def tlsa(cert_der=CERT, usage=3, selector=1, mtype=1):
    value = _spki_sha256(cert_der) if (selector, mtype) == (1, 1) else hashlib.sha256(cert_der).digest()
    return SimpleNamespace(usage=usage, selector=selector, mtype=mtype, cert=value)


def a_record():
    return SimpleNamespace(address='192.0.2.10')


def _install(monkeypatch, records, certificate=CERT):
    """records: {(name, rtype) or (name, rtype, 'cd'): DnssecAnswer | Exception}.
    Missing names answer NXDOMAIN. certificate: DER bytes or an Exception."""
    probes = []

    async def resolve(name, rtype='A', timeout=5, checking_disabled=False):
        key = (name, rtype, 'cd') if checking_disabled else (name, rtype)
        value = records.get(key, NX)
        if isinstance(value, Exception):
            raise value
        return value

    async def fetch(host):
        probes.append(host)
        if isinstance(certificate, Exception):
            raise certificate
        return certificate

    monkeypatch.setattr(domains, 'resolve_dnssec_with_fallback', resolve)
    monkeypatch.setattr(domains, '_fetch_mx_certificate', fetch)
    return probes


def _signed_zone(tlsa_records, tlsa_ad=True, mx_ad=True, address_ad=True):
    return {
        ('example.test', 'MX'): ok([mx()], ad=mx_ad),
        (MX, 'A'): ok([a_record()], ad=address_ad),
        (f'_25._tcp.{MX}', 'TLSA'): ok(tlsa_records, ad=tlsa_ad),
    }


def dnssec(monkeypatch, records):
    _install(monkeypatch, records)
    return asyncio.run(domains.check_dnssec_record('example.test'))


def dane_check(monkeypatch, records, certificate=CERT):
    probes = _install(monkeypatch, records, certificate)
    return asyncio.run(domains.check_tlsa_record('example.test')), probes


# --- DNSSEC -----------------------------------------------------------------

def test_validated_domain_passes(monkeypatch):
    result = dnssec(monkeypatch, {('example.test', 'SOA'): ok([object()], ad=True)})
    assert result['status'] == 'success'
    assert result['validated'] is True


def test_unsigned_domain_is_a_warning(monkeypatch):
    result = dnssec(monkeypatch, {('example.test', 'SOA'): ok([object()], ad=False)})
    assert result['status'] == 'warning'
    assert result['message'] == 'DNSSEC not enabled for this domain'
    assert result['validated'] is False


def test_keys_without_ds_are_named(monkeypatch):
    result = dnssec(monkeypatch, {
        ('example.test', 'SOA'): ok([object()], ad=False),
        ('example.test', 'DNSKEY'): ok([object()], ad=False),
    })
    assert result['status'] == 'warning'
    assert 'DS record is missing' in result['message']


def test_broken_signature_is_an_error(monkeypatch):
    """SERVFAIL that goes away with checking disabled means DNSSEC is bogus:
    validating resolvers cannot resolve the domain at all."""
    result = dnssec(monkeypatch, {
        ('example.test', 'SOA'): SERVFAIL,
        ('example.test', 'SOA', 'cd'): ok([object()], ad=False),
    })
    assert result['status'] == 'error'
    assert 'validation fails' in result['message']


def test_servfail_without_dnssec_cause_is_unknown(monkeypatch):
    result = dnssec(monkeypatch, {
        ('example.test', 'SOA'): SERVFAIL,
        ('example.test', 'SOA', 'cd'): SERVFAIL,
    })
    assert result['status'] == 'unknown'


def test_resolver_failure_is_unknown_not_unsigned(monkeypatch):
    result = dnssec(monkeypatch, {('example.test', 'SOA'): Exception('all resolvers failed')})
    assert result['status'] == 'unknown'
    assert result['validated'] is None


# --- DANE -------------------------------------------------------------------

def test_working_dane_passes(monkeypatch):
    result, probes = dane_check(monkeypatch, _signed_zone([tlsa()]))
    assert result['status'] == 'success'
    assert result['dane_active'] is True
    assert result['message'].startswith('DANE active')
    assert result['certificate_mismatch'] == []
    assert result['hosts'][0]['certificate'] == 'match'
    assert probes == [MX]


def test_full_certificate_sha256_record_matches(monkeypatch):
    result, _ = dane_check(monkeypatch, _signed_zone([tlsa(selector=0, mtype=1)]))
    assert result['hosts'][0]['certificate'] == 'match'


def test_mismatch_with_dnssec_is_an_error(monkeypatch):
    """The dangerous case: DANE senders refuse to deliver."""
    result, _ = dane_check(monkeypatch, _signed_zone([tlsa()]), certificate=OTHER_CERT)
    assert result['status'] == 'error'
    assert 'does not match the certificate of ' + MX in result['message']
    assert result['certificate_mismatch'] == [MX]


def test_mismatch_without_dnssec_is_a_warning(monkeypatch):
    result, _ = dane_check(monkeypatch, _signed_zone([tlsa()], tlsa_ad=False), certificate=OTHER_CERT)
    assert result['status'] == 'warning'
    assert 'once DNSSEC is enabled' in result['message']
    assert result['certificate_mismatch'] == []


def test_records_without_dnssec_are_not_active(monkeypatch):
    result, _ = dane_check(monkeypatch, _signed_zone([tlsa()], mx_ad=False, address_ad=False))
    assert result['status'] == 'warning'
    assert result['dane_active'] is False
    assert 'not DNSSEC validated' in result['message']
    assert any('MX records of example.test' in w and f'address of {MX}' in w for w in result['warnings'])


def test_unreachable_port_25_is_not_a_mismatch(monkeypatch):
    result, _ = dane_check(monkeypatch, _signed_zone([tlsa()]),
                           certificate=dane.CertificateUnavailable('timed out'))
    assert result['status'] == 'success'
    assert 'certificate not compared' in result['message']
    assert result['certificate_mismatch'] == []
    assert result['hosts'][0]['certificate'] == 'unreachable'
    assert any('could not connect on port 25' in line for line in result['info'])


def test_dane_ta_only_is_not_probed(monkeypatch):
    result, probes = dane_check(monkeypatch, _signed_zone([tlsa(usage=2)]))
    assert probes == []
    assert result['hosts'][0]['certificate'] == 'not_verifiable'


def test_no_tlsa_is_definitely_absent(monkeypatch):
    records = _signed_zone([])
    result, probes = dane_check(monkeypatch, records)
    assert result['status'] == 'warning'
    assert domains._definitely_absent(result)
    assert probes == []


def test_failed_tlsa_lookup_is_not_absent(monkeypatch):
    records = _signed_zone([])
    records[(f'_25._tcp.{MX}', 'TLSA')] = SERVFAIL
    result, _ = dane_check(monkeypatch, records)
    assert result['status'] == 'unknown'
    assert not domains._definitely_absent(result)


def test_null_mx_is_skipped(monkeypatch):
    result, _ = dane_check(monkeypatch, {('example.test', 'MX'): ok([SimpleNamespace(exchange='.')])})
    assert result['status'] == 'unknown'
    assert 'null MX' in result['message']


# --- TLSA matching ------------------------------------------------------------

@pytest.mark.parametrize('selector, mtype, expected', [
    (0, 0, lambda c: c),
    (0, 1, lambda c: hashlib.sha256(c).digest()),
    (0, 2, lambda c: hashlib.sha512(c).digest()),
    (1, 1, _spki_sha256),
])
def test_tlsa_association(selector, mtype, expected):
    assert dane.tlsa_association(CERT, selector, mtype) == expected(CERT)


def test_only_dane_ee_records_match():
    record = {'usage': 2, 'selector': 1, 'matching_type': 1, 'certificate': _spki_sha256(CERT).hex()}
    assert not dane.matches_certificate(record, CERT)
    assert dane.matches_certificate({**record, 'usage': 3}, CERT)


def test_certificate_probe_is_cached(monkeypatch):
    calls = []

    def fake_sync(host):
        calls.append(host)
        if host == 'down.example.test':
            raise dane.CertificateUnavailable('connection refused')
        return CERT

    monkeypatch.setattr(dane, '_fetch_certificate_sync', fake_sync)
    monkeypatch.setattr(dane, '_cert_cache', {})
    assert asyncio.run(dane.fetch_smtp_certificate(MX)) == CERT
    assert asyncio.run(dane.fetch_smtp_certificate(MX.upper() + '.')) == CERT
    for _ in range(2):
        with pytest.raises(dane.CertificateUnavailable):
            asyncio.run(dane.fetch_smtp_certificate('down.example.test'))
    assert calls == [MX, 'down.example.test']


# --- change alerts --------------------------------------------------------------

class Prev:
    spf_check = dkim_check = dmarc_check = mta_sts_check = None
    dnssec_check = {'status': 'success', 'message': 'DNSSEC signed and validated', 'record': None}
    tlsa_check = {'status': 'success', 'record': '3 1 1 aa', 'certificate_mismatch': []}


def test_losing_dnssec_alerts():
    changes = domains.detect_dns_changes(Prev(), {
        'dnssec': {'status': 'error', 'message': 'DNSSEC validation fails', 'record': None}})
    assert changes == [{'type': 'DNSSEC', 'old': 'DNSSEC signed and validated',
                        'new': 'DNSSEC validation fails'}]


def test_dnssec_lookup_failure_does_not_alert():
    assert domains.detect_dns_changes(Prev(), {
        'dnssec': {'status': 'unknown', 'message': 'DNS lookup failed', 'record': None}}) == []


def test_new_certificate_mismatch_alerts_once():
    mismatch = {'status': 'error', 'record': '3 1 1 aa', 'certificate_mismatch': [MX]}
    changes = domains.detect_dns_changes(Prev(), {'tlsa': mismatch})
    assert [c['type'] for c in changes] == ['DANE']
    assert MX in changes[0]['new']

    class StillBroken(Prev):
        tlsa_check = mismatch
    assert domains.detect_dns_changes(StillBroken(), {'tlsa': mismatch}) == []


# --- resolver -----------------------------------------------------------------

def test_resolve_dnssec_reads_ad_flag_and_skips_servfail(monkeypatch):
    sent = []

    async def fake_udp(q, server, timeout=5):
        sent.append((server, q.flags, q.ednsflags))
        response = dns.message.make_response(q)
        if server == '8.8.8.8':
            response.set_rcode(dns.rcode.SERVFAIL)
        else:
            response.flags |= dns.flags.AD
        return response, False

    monkeypatch.setattr(dns_resolver.dns.asyncquery, 'udp_with_fallback', fake_udp)
    answer = asyncio.run(dns_resolver.resolve_dnssec('example.test', 'SOA', checking_disabled=True))
    assert answer.rcode == dns.rcode.NOERROR
    assert answer.authenticated is True
    assert [s for s, _, _ in sent] == ['8.8.8.8', '8.8.4.4']
    _, flags, ednsflags = sent[0]
    assert flags & dns.flags.CD and flags & dns.flags.AD
    assert ednsflags & dns.flags.DO
