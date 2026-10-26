"""Every answer the Domains calls can give, so the contract check (conftest.py,
contract.py) holds each one to /openapi.json: a DNS check of a domain in every
branch of every check (record found, missing, invalid, lookup failed, timed
out), the domain list with stored checks, checking every domain, mailcow
failing (502), the database failing (500) and a domain name the call refuses
(400). DNS, the MTA-STS policy fetch, the port 25 probe and mailcow are faked;
nothing leaves the test."""
import datetime
import hashlib
import time
import uuid
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

import dns.exception  # noqa: E402
import dns.rcode  # noqa: E402
import dns.resolver  # noqa: E402
import httpx  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import database  # noqa: E402
from app.config import settings  # noqa: E402
from app.mailcow_api import MailcowAPIError, mailcow_api  # noqa: E402
from app.main import app  # noqa: E402
from app.routers import domains  # noqa: E402
from app.services import alias_domains, dane  # noqa: E402
from app.services.dns_resolver import DnssecAnswer  # noqa: E402

MARK = uuid.uuid4().hex[:8]
ZONE = f'{MARK}.example'
SERVER_IP = '192.0.2.10'
KEY = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx'


# ---------------------------------------------------------------- fake DNS records

class TXT:
    def __init__(self, text):
        self.strings = [text.encode()]


class Addr:
    def __init__(self, ip):
        self.ip = ip

    def __str__(self):
        return self.ip


def mx(host, preference=10):
    return SimpleNamespace(exchange=host + '.', preference=preference)


def ok(records=(), ad=True):
    return DnssecAnswer(dns.rcode.NOERROR, ad, list(records))


NX = DnssecAnswer(dns.rcode.NXDOMAIN, True, [])
SERVFAIL = DnssecAnswer(dns.rcode.SERVFAIL, False, [])


def _certificate(name):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


CERT = _certificate('mx.example')
OTHER_CERT = _certificate('other.example')


def tlsa(cert_der=CERT, usage=3, selector=1, mtype=1):
    if selector == 1:
        data = x509.load_der_x509_certificate(cert_der).public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    else:
        data = cert_der
    return SimpleNamespace(usage=usage, selector=selector, mtype=mtype, cert=hashlib.sha256(data).digest())


# ---------------------------------------------------------------- every branch of every check
# Each variant is (records, the start of the message it gives). Domain i takes
# variant i of each check (cycled), so one call reaches one branch of each.

def spf_variants(d):
    return [
        ({(d, 'TXT'): [TXT(f'v=spf1 a mx:mx-spf.{d} include:_spf.{d} -all'), TXT('site-verification=x')],
          (d, 'A'): [Addr(SERVER_IP)], (f'mx-spf.{d}', 'MX'): [mx(f'out.{d}')],
          (f'out.{d}', 'A'): [Addr('192.0.2.20')], (f'_spf.{d}', 'TXT'): [TXT('v=spf1 ip6:2001:db8::/32 ~all')]},
         'SPF configured correctly'),
        ({}, 'Domain does not exist'),
        ({(d, 'TXT'): dns.resolver.NoAnswer()}, 'No TXT records found'),
        ({(d, 'TXT'): [TXT('v=spf1 -all'), TXT('v=spf1 ~all')]}, 'Multiple SPF records'),
        ({(d, 'TXT'): [TXT('site-verification=x')]}, 'SPF record not found'),
        ({(d, 'TXT'): [TXT('v=spf1-all')]}, 'Invalid SPF syntax'),
        ({(d, 'TXT'): [TXT('v=spf1 ip4:mail.example -all')]}, 'Invalid SPF mechanisms'),
        ({(d, 'TXT'): [TXT(f'v=spf1 ip4:{SERVER_IP}')]}, 'SPF record missing "all"'),
        ({(d, 'TXT'): [TXT('v=spf1 +all')]}, 'SPF uses +all'),
        ({(d, 'TXT'): [TXT('v=spf1 ' + 'a ' * 11 + '-all')]}, 'SPF has too many DNS lookups'),
        ({(d, 'TXT'): [TXT('v=spf1 ip4:203.0.113.1 -all')]}, f'Server IP {SERVER_IP} is NOT authorized'),
        ({(d, 'TXT'): [TXT(f'v=spf1 ptr ip4:{SERVER_IP} ?all')]}, 'SPF uses ?all'),
        ({(d, 'TXT'): [TXT(f'v=spf1 ip4={SERVER_IP} redirect=_spf.{d}')],
          (f'_spf.{d}', 'TXT'): [TXT(f'v=spf1 ip4:{SERVER_IP} -all')]}, f'SPF redirects to _spf.{d}'),
        ({(d, 'TXT'): dns.exception.Timeout()}, 'Failed to check SPF'),
        ({(d, 'TXT'): [TXT(f'v=spf1 ip4:{SERVER_IP} ~all')]}, 'SPF uses ~all'),
    ]


MAILCOW_DKIM = {'dkim_selector': 'dkim', 'dkim_txt': f'v=DKIM1;k=rsa;t=s;s=email;p={KEY}', 'length': '2048'}


def dkim_variants(d):
    """(mailcow's answer, records, message)"""
    at = f'dkim._domainkey.{d}'
    return [
        (MAILCOW_DKIM, {(at, 'TXT'): [TXT(f'v=DKIM1; k=rsa; t=s; s=email; p={KEY}')]}, 'DKIM configured correctly'),
        ([], {}, 'DKIM not configured in mailcow'),
        (['unexpected'], {}, 'Invalid DKIM configuration format'),
        ({'dkim_selector': 'dkim', 'dkim_txt': ''}, {}, 'DKIM record is empty'),
        (MAILCOW_DKIM, {}, 'DKIM record not found'),
        (MAILCOW_DKIM, {(at, 'TXT'): dns.resolver.NoAnswer()}, 'No TXT record at'),
        (MAILCOW_DKIM, {(at, 'TXT'): dns.exception.Timeout()}, 'DNS query timeout'),
        (MAILCOW_DKIM, {(at, 'TXT'): [TXT('v=DKIM1; k=ed25519; t=y; h=sha1; p=OTHER')]}, 'DKIM is in TESTING mode'),
        (MAILCOW_DKIM, {(at, 'TXT'): [TXT(f'v=DKIM1; k=rsa; h=sha256; p={KEY}')]}, 'DKIM configured but has warnings'),
        (MailcowAPIError('down'), {}, 'Failed to check DKIM'),
        (MAILCOW_DKIM, {(at, 'TXT'): [TXT('v=DKIM1; k=rsa; p=')]}, 'DKIM record mismatch'),
    ]


def dmarc_variants(d):
    at = f'_dmarc.{d}'
    return [
        ({(at, 'TXT'): [TXT(f'v=DMARC1; p=reject; sp=quarantine; rua=mailto:dmarc@{d},mailto:x@{d}; '
                            f'ruf=mailto:f@{d}; adkim=s; aspf=r; pct=100; fo=1')]}, 'DMARC configured with reject'),
        ({}, 'DMARC record not found'),
        ({(at, 'TXT'): dns.resolver.NoAnswer()}, 'No DMARC record configured'),
        ({(at, 'TXT'): [TXT('v=spf1 -all')]}, 'DMARC record not found'),
        ({(at, 'TXT'): [TXT('v=DMARC1; p=none; pct=abc')]}, 'DMARC policy is too weak (none)'),
        ({(at, 'TXT'): dns.exception.Timeout()}, 'Failed to check DMARC'),
        ({(at, 'TXT'): [TXT('v=DMARC1; rua=mailto:a@b.example')]}, 'DMARC policy is too weak (unknown)'),
    ]


def dnssec_variants(d):
    return [
        ({(d, 'SOA'): ok([object()])}, 'DNSSEC signed and validated'),
        ({(d, 'SOA'): RuntimeError('All DNS resolvers failed')}, 'Could not check DNSSEC'),
        ({(d, 'SOA'): SERVFAIL, (d, 'SOA', 'cd'): ok([object()], ad=False)}, 'DNSSEC validation fails'),
        ({(d, 'SOA'): SERVFAIL, (d, 'SOA', 'cd'): RuntimeError('down')}, 'DNS lookup failed'),
        ({}, 'Domain not found in DNS'),
        ({(d, 'SOA'): ok([object()], ad=False), (d, 'DNSKEY'): ok([object()], ad=False)},
         'DNSSEC keys are published but not validated'),
        ({(d, 'SOA'): ok([object()], ad=False)}, 'DNSSEC not enabled'),
    ]


def tlsa_variants(d):
    """(DNSSEC records, certificates by host, message)"""
    mx1, mx2, mx3 = f'mx1.{d}', f'mx2.{d}', f'mx3.{d}'

    def at(host):
        return f'_25._tcp.{host}'
    address = Addr('192.0.2.25')
    return [
        ({(d, 'MX'): ok([mx(mx1)]), (mx1, 'A'): ok([address]), (at(mx1), 'TLSA'): ok([tlsa()])},
         {mx1: CERT}, 'DANE active - TLSA records validated and matching'),
        ({}, {}, 'No MX records found'),
        ({(d, 'MX'): ok([SimpleNamespace(exchange='.', preference=0)])}, {}, 'Domain does not accept mail'),
        ({(d, 'MX'): RuntimeError('All DNS resolvers failed')}, {}, 'Could not look up MX records'),
        ({(d, 'MX'): ok([mx(mx1)])}, {}, 'No DANE/TLSA records published'),
        ({(d, 'MX'): ok([mx(mx1)]), (at(mx1), 'TLSA'): RuntimeError('down')}, {}, 'Could not look up TLSA records'),
        ({(d, 'MX'): ok([mx(f'mx{n}.{d}', n) for n in range(12)])}, {}, 'No TLSA records on the 10 mail servers'),
        ({(d, 'MX'): ok([mx(mx1, 10), mx(mx2, 20), mx(mx3, 30)]), (mx1, 'A'): ok([address]),
          (at(mx1), 'TLSA'): ok([tlsa()]), (at(mx3), 'TLSA'): SERVFAIL},
         {mx1: OTHER_CERT}, 'TLSA record does not match the certificate of'),
        ({(d, 'MX'): ok([mx(mx1)], ad=False), (mx1, 'A'): ok([address]), (at(mx1), 'TLSA'): ok([tlsa()], ad=False)},
         {mx1: OTHER_CERT}, 'TLSA record does not match the certificate of'),
        ({(d, 'MX'): ok([mx(mx1)]), (mx1, 'A'): ok([]), (mx1, 'AAAA'): ok([Addr('2001:db8::25')], ad=False),
          (at(mx1), 'TLSA'): ok([tlsa()])},
         {mx1: dane.CertificateUnavailable('timed out')}, 'TLSA records are published but not DNSSEC validated'),
        ({(d, 'MX'): ok([mx(mx1), mx(mx2)]), (mx1, 'A'): ok([address]),
          (at(mx1), 'TLSA'): ok([tlsa(usage=2, selector=0)]), (mx2, 'A'): RuntimeError('down'),
          (at(mx2), 'TLSA'): ok([tlsa()])},
         {mx2: dane.ProbeBusy('too many probes')}, 'DANE active - TLSA records validated, certificate not compared'),
    ]


def mta_sts_variants(d):
    """(records, the policy file or why it cannot be fetched, message)"""
    at = f'_mta-sts.{d}'
    policy = f'version: STSv1\nmode: enforce\nmx: *.{d}\nmax_age: 604800\n'
    elsewhere = [mx('mx.elsewhere.example')]
    return [
        ({(at, 'TXT'): [TXT('v=STSv1; id=20260101;')], (d, 'MX'): [mx(f'mail.{d}')]}, policy, 'MTA-STS enforced'),
        ({}, None, 'MTA-STS record not published'),
        ({(at, 'TXT'): dns.exception.Timeout()}, None, 'Could not check MTA-STS record'),
        ({(at, 'TXT'): [TXT('v=STSv1; id=1;'), TXT('v=STSv1; id=2;')]}, None, '2 MTA-STS records published'),
        ({(at, 'TXT'): [TXT('v=STSv1; id=1;')]}, httpx.ConnectError('refused'),
         'MTA-STS record exists but the policy file could not be fetched'),
        ({(at, 'TXT'): [TXT('v=STSv1; id=1;')]}, 'mode: enforce\n', 'MTA-STS policy file is missing'),
        ({(at, 'TXT'): [TXT('v=STSv1; id=1;')]}, 'version: STSv1\nmode: strict\n', 'MTA-STS policy has an invalid mode'),
        ({(at, 'TXT'): [TXT('v=STSv1; id=1;')], (d, 'MX'): elsewhere}, policy, 'MX not covered by the enforced'),
        ({(at, 'TXT'): [TXT('v=STSv1')], (d, 'MX'): elsewhere}, policy.replace('enforce', 'testing'),
         'MTA-STS policy is in testing mode'),
        ({(at, 'TXT'): [TXT('v=STSv1; id=1;')], (d, 'MX'): dns.exception.Timeout()},
         'version: STSv1\nmode: none\nmax_age: 86400\n', 'MTA-STS policy mode is "none"'),
    ]


def tls_rpt_variants(d):
    at = f'_smtp._tls.{d}'
    return [
        ({(at, 'TXT'): [TXT(f'v=TLSRPTv1; rua=mailto:tls@{d},ftp://reports.{d}')]}, 'TLS-RPT configured'),
        ({}, 'TLS-RPT record not published'),
        ({(at, 'TXT'): [TXT('v=TLSRPTv1; rua=mailto:a@b.example'), TXT('v=TLSRPTv1; rua=mailto:c@d.example')]},
         '2 TLS-RPT records published'),
        ({(at, 'TXT'): [TXT('v=TLSRPTv1; rua=ftp://reports.example')]}, 'TLS-RPT record has no valid rua'),
        ({(at, 'TXT'): dns.exception.Timeout()}, 'Could not check TLS-RPT record'),
    ]


SCENARIOS = max(len(f('x')) for f in (spf_variants, dkim_variants, dmarc_variants, dnssec_variants,
                                       tlsa_variants, mta_sts_variants, tls_rpt_variants))


def scenario_domain(n):
    return f'c{n}.{ZONE}'


def build_world(world, n):
    """Put domain n's records in the fake DNS, mailcow and probes; return the messages each check gives."""
    d = scenario_domain(n)

    def pick(variants):
        return variants[n % len(variants)]

    spf, spf_message = pick(spf_variants(d))
    dkim_answer, dkim_records, dkim_message = pick(dkim_variants(d))
    dmarc, dmarc_message = pick(dmarc_variants(d))
    dnssec, dnssec_message = pick(dnssec_variants(d))
    tlsa_records, certificates, tlsa_message = pick(tlsa_variants(d))
    mta_sts, policy, mta_sts_message = pick(mta_sts_variants(d))
    tls_rpt, tls_rpt_message = pick(tls_rpt_variants(d))
    for records in (spf, dkim_records, dmarc, mta_sts, tls_rpt):
        world['dns'].update(records)
    world['dnssec'].update(dnssec)
    world['dnssec'].update(tlsa_records)
    world['dkim'][d] = dkim_answer
    world['certificates'].update(certificates)
    if policy is not None:
        world['policies'][d] = policy
    return {'spf': spf_message, 'dkim': dkim_message, 'dmarc': dmarc_message, 'dnssec': dnssec_message,
            'tlsa': tlsa_message, 'mta_sts': mta_sts_message, 'tls_rpt': tls_rpt_message}


# ---------------------------------------------------------------- fixtures

class _Broken:
    def __getattr__(self, name):
        raise RuntimeError('database gone')


@contextmanager
def _broken_context():
    yield _Broken()


def _postgres_available() -> bool:
    try:
        with database.engine.connect():
            return True
    except Exception:
        return False


@pytest.fixture
def world(monkeypatch):
    """Fake DNS, MTA-STS policies, port 25 certificates and mailcow. A name the world
    does not have answers NXDOMAIN; nothing is looked up or fetched for real."""
    for key in ('auth_enabled', 'basic_auth_enabled', 'oauth2_enabled'):
        monkeypatch.setattr(settings._inner, key, False)
    # No change alert is sent; the SPF sources are the server's IP and the DMARC history
    monkeypatch.setattr(settings._inner, 'dns_change_alerts_enabled', False)
    monkeypatch.setattr(settings._inner, 'domain_spf_source_server_ip', True)
    monkeypatch.setattr(settings._inner, 'domain_spf_source_transports', False)
    monkeypatch.setattr(settings._inner, 'domain_spf_source_relayhosts', False)
    monkeypatch.setattr(settings._inner, 'domain_spf_source_manual_hosts', '')
    monkeypatch.setattr(settings._inner, 'domain_spf_source_dmarc_history', True)
    monkeypatch.setattr(domains, '_server_ip_cache', SERVER_IP)
    state = {'dns': {}, 'dnssec': {}, 'dkim': {}, 'policies': {}, 'certificates': {}, 'domains': []}

    async def resolve(name, rtype='TXT', timeout=5):
        value = state['dns'].get((name, rtype))
        if value is None:
            raise dns.resolver.NXDOMAIN()
        if isinstance(value, Exception):
            raise value
        return value

    async def resolve_dnssec(name, rtype='A', timeout=5, checking_disabled=False):
        value = state['dnssec'].get((name, rtype, 'cd') if checking_disabled else (name, rtype), NX)
        if isinstance(value, Exception):
            raise value
        return value

    async def fetch_policy(domain):
        value = state['policies'].get(domain, ValueError('no policy host'))
        if isinstance(value, Exception):
            raise value
        return value

    async def fetch_certificate(host):
        value = state['certificates'].get(host, dane.CertificateUnavailable('no answer on port 25'))
        if isinstance(value, Exception):
            raise value
        return value

    async def mailcow(endpoint, method='GET', **kwargs):
        if endpoint == '/api/v1/get/domain/all':
            value = state['domains']
        elif endpoint.startswith('/api/v1/get/dkim/'):
            value = state['dkim'].get(endpoint.rsplit('/', 1)[1], [])
        else:
            raise AssertionError(f'unexpected mailcow call {endpoint}')
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(domains, 'resolve_dns_with_fallback', resolve)
    monkeypatch.setattr(domains, 'resolve_dnssec_with_fallback', resolve_dnssec)
    monkeypatch.setattr(domains, '_fetch_mta_sts_policy', fetch_policy)
    monkeypatch.setattr(domains, '_fetch_mx_certificate', fetch_certificate)
    monkeypatch.setattr(mailcow_api, '_make_request', mailcow)
    # The alias domains come from memory, not the map stored for the app
    monkeypatch.setattr(alias_domains, '_cache', {})
    monkeypatch.setattr(alias_domains, '_cache_loaded_at', time.monotonic())
    return state


@pytest.fixture
def client(world):
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def stored(world):
    """The checks these tests store, and the time of the last full check, put back after."""
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.models import DomainDNSCheck, SystemSetting
    database.init_db()
    with database.get_db_context() as db:
        row = db.query(SystemSetting).filter(SystemSetting.key == domains.DNS_FULL_CHECK_KEY).first()
        before = (row.value, row.updated_at) if row else None
    yield
    with database.get_db_context() as db:
        db.query(DomainDNSCheck).filter(DomainDNSCheck.domain_name.like(f'%.{ZONE}')).delete(
            synchronize_session=False)
        row = db.query(SystemSetting).filter(SystemSetting.key == domains.DNS_FULL_CHECK_KEY).first()
        if before is None:
            if row is not None:
                db.delete(row)
        elif row is None:
            db.add(SystemSetting(key=domains.DNS_FULL_CHECK_KEY, value=before[0], updated_at=before[1]))
        else:
            row.value, row.updated_at = before
        db.commit()


def mailcow_domain(name, active=1, **values):
    domain = {'domain_name': name, 'active': active, 'mboxes_in_domain': 2, 'mboxes_left': 8,
              'max_num_mboxes_for_domain': 10, 'aliases_in_domain': 1, 'aliases_left': 399,
              'max_num_aliases_for_domain': 400, 'created': '2025-03-01 10:00:00', 'bytes_total': '1048576',
              'msgs_total': '42', 'quota_used_in_domain': '1048576', 'max_quota_for_domain': 10737418240,
              'backupmx': 0, 'relay_all_recipients': 0, 'relay_unknown_only': 0, 'gal': 1, 'description': ''}
    domain.update(values)
    return domain


# ---------------------------------------------------------------- POST /api/domains/{domain}/check-dns

@pytest.mark.parametrize('n', range(SCENARIOS))
def test_check_one_domain_in_every_branch(client, world, stored, n):
    expected = build_world(world, n)
    domain = scenario_domain(n)
    response = client.post(f'/api/domains/{domain}/check-dns')
    assert response.status_code == 200, response.text
    body = response.json()
    assert body['status'] == 'success'
    data = body['data']
    assert data['domain'] == domain
    for check, message in expected.items():
        assert data[check]['message'].startswith(message), (check, data[check]['message'])


def test_check_one_domain_refuses_a_name_that_is_not_a_domain(client):
    response = client.post('/api/domains/not_a_domain!/check-dns')
    assert response.status_code == 400
    assert response.json() == {'detail': 'Invalid domain name'}


def test_check_one_domain_when_the_database_fails(client, monkeypatch):
    monkeypatch.setattr(domains, 'get_db_context', _broken_context)
    response = client.post(f'/api/domains/{scenario_domain(0)}/check-dns')
    assert response.status_code == 500


# ---------------------------------------------------------------- GET /api/domains/all

def test_domain_list_with_stored_checks(client, world, stored, monkeypatch):
    from app.models import DomainDNSCheck
    checked, alias, alias_unchecked = scenario_domain(0), f'alias.{ZONE}', f'alias2.{ZONE}'
    build_world(world, 0)
    assert client.post(f'/api/domains/{checked}/check-dns').status_code == 200
    assert client.post(f'/api/domains/{alias}/check-dns').status_code == 200
    # A row stored by an older version: checks added since are null, an old error text is cut
    with database.get_db_context() as db:
        db.add(DomainDNSCheck(
            domain_name=f'old.{ZONE}', checked_at=datetime.datetime.utcnow(),
            spf_check={'status': 'error', 'message': 'Failed to check SPF: timed out', 'record': None,
                       'has_strict_all': False, 'includes_mx': False, 'includes': []}))
        db.commit()
    monkeypatch.setattr(alias_domains, '_cache', {alias: checked, alias_unchecked: checked})
    world['domains'] = [
        mailcow_domain(checked),
        mailcow_domain(f'old.{ZONE}', active=0, created='not a date', backupmx=1),
        {'domain_name': f'new.{ZONE}', 'active': 1},  # what mailcow leaves out reads as 0
        {'domain_name': ''},
    ]
    response = client.get('/api/domains/all')
    assert response.status_code == 200, response.text
    body = response.json()
    assert (body['total'], body['active']) == (3, 2)
    first, old, new = body['domains']
    assert first['dns_checks']['spf']['message'].startswith('SPF configured correctly')
    assert [a['domain_name'] for a in first['alias_domains']] == [alias, alias_unchecked]
    assert first['alias_domains'][0]['dns_checks']['dkim']['message'] == 'DKIM not configured in mailcow'
    assert first['alias_domains'][1]['dns_checks'] == {}
    assert old['dns_checks']['spf']['message'] == 'Failed to check SPF. Check the application logs.'
    assert old['dns_checks']['tlsa'] is None and old['created'] == 'not a date'
    assert new['dns_checks'] == {} and new['mboxes_in_domain'] == 0


def test_domain_list_without_domains(client, world, stored):
    world['domains'] = []
    response = client.get('/api/domains/all')
    assert response.status_code == 200
    assert response.json()['domains'] == []


def test_domain_list_when_mailcow_fails(client, world):
    world['domains'] = MailcowAPIError('down')
    assert client.get('/api/domains/all').status_code == 502


def test_domain_list_when_the_database_fails(client, world, monkeypatch):
    world['domains'] = [mailcow_domain(scenario_domain(0))]
    monkeypatch.setattr(domains, 'get_db_context', _broken_context)
    assert client.get('/api/domains/all').status_code == 500


# ---------------------------------------------------------------- POST /api/domains/check-all-dns

def test_check_every_domain(client, world, stored, monkeypatch):
    first, inactive, alias = scenario_domain(0), scenario_domain(1), f'alias.{ZONE}'
    build_world(world, 0)
    build_world(world, 1)
    world['domains'] = [mailcow_domain(first), mailcow_domain(inactive, active=0)]
    monkeypatch.setattr(alias_domains, '_cache', {alias: first})
    response = client.post('/api/domains/check-all-dns')
    assert response.status_code == 200, response.text
    assert response.json() == {'status': 'success', 'message': 'Checked 2 domains', 'domains_checked': 2,
                               'errors': []}
    assert client.get('/api/domains/all').json()['last_dns_check'] is not None


def test_check_every_domain_without_domains(client, world):
    world['domains'] = []
    response = client.post('/api/domains/check-all-dns')
    assert response.status_code == 200
    assert response.json()['message'] == 'No domains to check'


def test_check_every_domain_when_results_cannot_be_stored(client, world, monkeypatch):
    """With the database gone each result fails to store, and the answer lists them.
    The alias domains are read from memory, so that read does not fail."""
    world['domains'] = [mailcow_domain(scenario_domain(0)), mailcow_domain(scenario_domain(1))]
    monkeypatch.setattr(domains, 'get_db_context', _broken_context)
    response = client.post('/api/domains/check-all-dns')
    assert response.status_code == 200, response.text
    body = response.json()
    assert (body['status'], body['domains_checked'], len(body['errors'])) == ('partial', 0, 2)


def test_check_every_domain_when_mailcow_fails(client, world):
    world['domains'] = MailcowAPIError('down')
    assert client.post('/api/domains/check-all-dns').status_code == 502


def test_check_every_domain_when_mailcow_sends_a_domain_that_is_not_an_object(client, world):
    """A database that fails cannot stop this call (see above); a domain list it cannot read can."""
    world['domains'] = [mailcow_domain(scenario_domain(0)), 'not a domain']
    assert client.post('/api/domains/check-all-dns').status_code == 500
