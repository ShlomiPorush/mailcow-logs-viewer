"""
The rest of the internet, as the demo sees it.

Every outbound path outside the mailcow API is replaced here with a fake
that answers like a healthy real installation: DNS (domain checks and
blocklists), HTTP (GitHub releases, help documents, MTA-STS policies,
MaxMind), SMTP, IMAP, notification webhooks and GeoIP. The network guard
stays in place underneath, so a path missed here fails closed instead of
reaching the network.

The zones are consistent with the fake mailcow server: SPF authorises the
server address mailcow reports, DKIM matches mailcow's key, and the MX,
TLSA and MTA-STS records point at the same mail host. The TLSA record pins
the certificate the fake mail host presents, and the signed zones answer as
DNSSEC validated, so DANE shows as working. The three hosted
domains are deliberately in different shape (all good, warnings, an error)
so the Domains page shows what the checks find.
"""
import datetime
import hashlib
import logging
from pathlib import Path

import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from . import world

logger = logging.getLogger(__name__)

# Copied next to the package in the demo image; the repository copy in a checkout
_HERE = Path(__file__).resolve().parent
HELP_DOCS_DIR = next((p for p in (_HERE / "HelpDocs", _HERE.parents[1] / "documentation" / "HelpDocs")
                      if p.is_dir()), _HERE / "HelpDocs")


def _mail_host_certificate() -> bytes:
    """The certificate the fake mail host presents over STARTTLS.

    The key is derived from a fixed seed, so the TLSA record below is the
    same on every start and never looks like a DNS change.
    """
    seed = int.from_bytes(hashlib.sha256(b"demo mail host key").digest(), "big")
    key = ec.derive_private_key(seed % (2 ** 255), ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, world.MAIL_HOST)])
    start = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(start).not_valid_after(start + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


MAIL_HOST_CERTIFICATE = _mail_host_certificate()
_TLSA_HASH = hashlib.sha256(
    x509.load_der_x509_certificate(MAIL_HOST_CERTIFICATE).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
).hexdigest()
_MX = f"10 {world.MAIL_HOST}."
_DKIM = f'"v=DKIM1;k=rsa;t=s;s=email;p={world.DKIM_KEY}"'
_SPF_STRICT = f'"v=spf1 mx ip4:{world.SERVER_IPV4} -all"'

# name -> {rdtype: [rdata text, ...]}. A name that is present answers
# NoAnswer for other types; a missing name answers NXDOMAIN.
ZONES = {
    # example.com: everything in order
    "example.com": {"TXT": [_SPF_STRICT, '"google-site-verification=demo-not-real"'], "MX": [_MX]},
    "dkim._domainkey.example.com": {"TXT": [_DKIM]},
    "_dmarc.example.com": {"TXT": ['"v=DMARC1; p=reject; rua=mailto:dmarc@example.com; adkim=s; aspf=s"']},
    "_mta-sts.example.com": {"TXT": ['"v=STSv1; id=20260901T000000"']},
    "_smtp._tls.example.com": {"TXT": ['"v=TLSRPTv1; rua=mailto:dmarc@example.com"']},
    # example.net: alias domain of example.com, same records
    "example.net": {"TXT": [_SPF_STRICT], "MX": [_MX]},
    "dkim._domainkey.example.net": {"TXT": [_DKIM]},
    "_dmarc.example.net": {"TXT": ['"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"']},
    # example.org: works, with warnings (soft-fail SPF, monitoring-only DMARC)
    "example.org": {"TXT": [f'"v=spf1 mx ip4:{world.SERVER_IPV4} ~all"'], "MX": [_MX]},
    "dkim._domainkey.example.org": {"TXT": [_DKIM]},
    "_dmarc.example.org": {"TXT": ['"v=DMARC1; p=none; rua=mailto:dmarc@example.org"']},
    # shop.test: no DMARC record at all
    "shop.test": {"TXT": [_SPF_STRICT], "MX": [_MX]},
    "dkim._domainkey.shop.test": {"TXT": [_DKIM]},
    # the mail host
    world.MAIL_HOST: {"A": [world.SERVER_IPV4], "AAAA": [world.SERVER_IPV6]},
    f"_25._tcp.{world.MAIL_HOST}": {"TLSA": [f"3 1 1 {_TLSA_HASH}"]},
}

# Zones signed with DNSSEC. example.org and shop.test are not, which the
# Domains page reports as a warning, in line with their other warnings.
SIGNED_ZONES = ("example.com", "example.net")

MTA_STS_POLICIES = {
    "example.com": f"version: STSv1\nmode: enforce\nmx: {world.MAIL_HOST}\nmax_age: 604800\n",
}

# The server address is listed on exactly one blocklist, so the Blocklist
# page shows both outcomes. UCEPROTECT level 3 lists whole networks, which is
# the most common harmless listing a real server sees.
LISTED = {(world.SERVER_IPV4, "dnsbl-3.uceprotect.net"): "127.0.0.2"}

# GeoIP: fixed answers for the world's addresses, a stable spread for any
# other address. ASNs are from the documentation range (RFC 5398).
_GEO_POOL = [
    ("DE", "Germany", "Frankfurt am Main"), ("NL", "Netherlands", "Amsterdam"),
    ("US", "United States", "Ashburn"), ("FR", "France", "Paris"),
    ("GB", "United Kingdom", "London"), ("SE", "Sweden", "Stockholm"),
    ("BR", "Brazil", "Sao Paulo"), ("IN", "India", "Mumbai"),
    ("VN", "Vietnam", "Hanoi"), ("CN", "China", "Shenzhen"),
    ("RU", "Russia", "Moscow"), ("SG", "Singapore", "Singapore"),
]
_GEO_FIXED = {
    world.SERVER_IPV4: ("DE", "Germany", "Frankfurt am Main", 64496, "Demo Hosting GmbH"),
    **{ip: ("DE", "Germany", "Berlin", 64497, "Demo Office Network") for ip in world.CLIENT_IPS},
}


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


# --------------------------------------------------------------------- DNS

def _normalize(name) -> str:
    return str(name).lower().rstrip(".")


async def resolve(query, rdtype="A", timeout=5, **kwargs):
    name = _normalize(query)
    rdtype = str(rdtype).upper()
    records = ZONES.get(name)
    if records is None:
        raise dns.resolver.NXDOMAIN()
    texts = records.get(rdtype)
    if not texts:
        raise dns.resolver.NoAnswer()
    rtype = dns.rdatatype.from_text(rdtype)
    return [dns.rdata.from_text(dns.rdataclass.IN, rtype, text) for text in texts]


def _signed(name: str) -> bool:
    return any(name == zone or name.endswith("." + zone) for zone in SIGNED_ZONES)


async def resolve_dnssec(query, rdtype="A", timeout=5, checking_disabled=False):
    from app.services.dns_resolver import DnssecAnswer
    name = _normalize(query)
    rdtype = str(rdtype).upper()
    records = ZONES.get(name)
    if records is None:
        return DnssecAnswer(dns.rcode.NXDOMAIN, _signed(name), [])
    rtype = dns.rdatatype.from_text(rdtype)
    answers = [dns.rdata.from_text(dns.rdataclass.IN, rtype, text) for text in records.get(rdtype, [])]
    return DnssecAnswer(dns.rcode.NOERROR, _signed(name), answers)


async def fetch_smtp_certificate(host):
    from app.services.dane import CertificateUnavailable
    if _normalize(host) == world.MAIL_HOST:
        return MAIL_HOST_CERTIFICATE
    raise CertificateUnavailable("connection refused")


async def resolve_for_blacklist(query, rdtype="A", timeout=10, **kwargs):
    name = _normalize(query)
    for (ip, zone), answer in LISTED.items():
        if ":" not in ip and name == ".".join(reversed(ip.split("."))) + "." + zone:
            return [dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, answer)]
    raise dns.resolver.NXDOMAIN()


# -------------------------------------------------------------------- HTTP

def _github_release(tag, body):
    return {"tag_name": tag, "name": tag, "body": body, "html_url": "https://github.com/",
            "published_at": _now().strftime("%Y-%m-%dT%H:%M:%SZ"), "draft": False, "prerelease": False}


def handle_http(request: httpx.Request) -> httpx.Response:
    host = request.url.host
    path = request.url.path
    if host == "api.github.com":
        from app.version import __version__
        if path == "/repos/ShlomiPorush/mailcow-logs-viewer/releases/latest":
            return httpx.Response(200, json=_github_release(
                f"v{__version__}", "You are running the latest version."))
        if path.startswith("/repos/ShlomiPorush/mailcow-logs-viewer/releases/tags/"):
            tag = path.rsplit("/", 1)[1]
            return httpx.Response(200, json=_github_release(
                tag, "Release notes are on GitHub. This demo does not load them."))
        if path == "/repos/mailcow/mailcow-dockerized/releases/latest":
            return httpx.Response(200, json=_github_release(
                world.MAILCOW_VERSION, "Fictional mailcow release used by the demo."))
    if host == "raw.githubusercontent.com" and "/documentation/HelpDocs/" in path:
        name = path.rsplit("/", 1)[1]
        doc = HELP_DOCS_DIR / name
        if doc.is_file() and doc.parent == HELP_DOCS_DIR:
            return httpx.Response(200, text=doc.read_text(encoding="utf-8"))
        return httpx.Response(404, text="Not found")
    if host.startswith("mta-sts.") and path == "/.well-known/mta-sts.txt":
        policy = MTA_STS_POLICIES.get(host[len("mta-sts."):])
        if policy:
            return httpx.Response(200, text=policy)
        return httpx.Response(404, text="Not found")
    if host == "secret-scanning.maxmind.com":
        return httpx.Response(204)
    logger.warning(f"[DEMO] No fake answer for {request.method} {request.url}; treating it as unreachable")
    raise httpx.ConnectError("demo mode: outbound network access is disabled", request=request)


_http_transport = httpx.MockTransport(handle_http)
_OriginalAsyncClient = httpx.AsyncClient


class DemoAsyncClient(_OriginalAsyncClient):
    """httpx.AsyncClient that answers from the fake internet unless the
    caller brings its own transport (the fake mailcow client does)."""

    def __init__(self, *args, **kwargs):
        if kwargs.get("transport") is None and kwargs.get("mounts") is None:
            kwargs["transport"] = _http_transport
        super().__init__(*args, **kwargs)


# ------------------------------------------------------- mail and webhooks

def _fake_send_email(self, recipient, subject, text_content, html_content=None):
    logger.warning(f"[DEMO] Email to {recipient} not sent (demo): {subject}")
    return True


def _fake_smtp_test():
    from app.config import settings
    host = settings.smtp_host or "smtp.example.com"
    return {"success": True, "logs": [
        "Starting SMTP connection test...",
        f"Host: {host}",
        f"Port: {settings.smtp_port or 587}",
        "Connecting...",
        "Connected. STARTTLS negotiated.",
        "Login successful.",
        "Demo mode: the test email was not sent.",
        "SMTP connection test completed successfully.",
    ]}


def _fake_imap_test():
    from app.config import settings
    host = settings.dmarc_imap_host or "imap.example.com"
    return {"success": True, "logs": [
        "Starting IMAP connection test...",
        f"Host: {host}",
        f"Port: {settings.dmarc_imap_port or 993}",
        "Connecting...",
        "Connected over SSL.",
        "Login successful.",
        f"Folder '{settings.dmarc_imap_folder}' selected: 0 new messages.",
        "IMAP connection test completed successfully.",
    ]}


def _fake_imap_sync(self, sync_type="auto"):
    """Record a successful sync that found nothing new; the demo's DMARC
    reports are seeded directly."""
    from app.database import SessionLocal
    from app.models import DMARCSync

    now = _now()
    record = DMARCSync(sync_type=sync_type, started_at=now, completed_at=now, status="success",
                       emails_found=0, emails_processed=0, reports_created=0,
                       reports_duplicate=0, reports_failed=0)
    db = SessionLocal()
    try:
        db.add(record)
        db.commit()
        db.refresh(record)
        return self._build_result(record)
    finally:
        db.close()


def _fake_send_to_config(channel_type, config, subject, message):
    logger.warning(f"[DEMO] Notification to {channel_type} not sent (demo): {subject}")
    return True, ""


def _fake_geoip_download(*args, **kwargs):
    logger.warning("[DEMO] GeoIP database download skipped (demo)")
    return False


# -------------------------------------------------------------------- GeoIP

def lookup_ip(ip_address):
    ip = str(ip_address)
    if ip in _GEO_FIXED:
        cc, country, city, asn, org = _GEO_FIXED[ip]
    else:
        digest = int(hashlib.sha256(ip.encode()).hexdigest(), 16)
        cc, country, city = _GEO_POOL[digest % len(_GEO_POOL)]
        asn = 64498 + digest % 14
        org = f"Example Network {asn - 64497}"
    return {"country_code": cc, "country_name": country, "city": city,
            "asn": f"AS{asn}", "asn_org": org}


def _geoip_available():
    return True


# ------------------------------------------------------------------ install

def install():
    from app.services import (connection_test, dane, dmarc_imap_service, dns_resolver,
                              geoip_downloader, geoip_service, notification_channels, smtp_service)
    from app.routers import settings as settings_router

    dns_resolver.resolve = resolve
    dns_resolver.resolve_dnssec = resolve_dnssec
    dane.fetch_smtp_certificate = fetch_smtp_certificate
    dns_resolver.resolve_for_blacklist = resolve_for_blacklist
    httpx.AsyncClient = DemoAsyncClient

    smtp_service.SmtpService.send_email = _fake_send_email
    connection_test.test_smtp_connection = _fake_smtp_test
    connection_test.test_imap_connection = _fake_imap_test
    settings_router.test_smtp_connection = _fake_smtp_test
    settings_router.test_imap_connection = _fake_imap_test
    dmarc_imap_service.DMARCImapService.sync_reports = _fake_imap_sync
    notification_channels.send_to_config = _fake_send_to_config
    geoip_downloader.download_single_database = _fake_geoip_download

    geoip_service.lookup_ip = lookup_ip
    geoip_service.is_geoip_available = _geoip_available
    logger.warning("[DEMO] DNS, HTTP, mail, webhooks and GeoIP answer from the fictional internet")
