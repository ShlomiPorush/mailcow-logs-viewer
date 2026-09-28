"""
DANE for SMTP (RFC 7672): fetch the certificate an MX host presents over
STARTTLS and compare it with its TLSA records.

Only DANE-EE (usage 3) can be verified here: it pins the server's own
certificate or key, which is what mailcow publishes ("3 1 1"). DANE-TA
(usage 2) pins an issuer in the chain, and Python 3.11 does not expose the
chain the server sent. PKIX usages 0 and 1 are not used for SMTP (RFC 7672
section 3.1.3), so senders ignore them.
"""
import asyncio
import hashlib
import logging
import smtplib
import socket
import ssl
import time
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)

SMTP_PORT = 25
SMTP_TIMEOUT = 10            # seconds for connect, banner, EHLO and STARTTLS
CERT_CACHE_SECONDS = 600     # many domains share one MX; probe it once per run

USAGE_DANE_TA = 2
USAGE_DANE_EE = 3

_cert_cache: Dict[str, Tuple[float, Optional[bytes], Optional[str]]] = {}


class CertificateUnavailable(Exception):
    """The certificate could not be fetched (port 25 blocked, no STARTTLS...)."""


def _ehlo_name() -> str:
    """A fully qualified name for EHLO. Many MX hosts drop a client that
    greets as "localhost", so use the mailcow hostname this app runs next to."""
    try:
        from app.config import settings
        name = urlparse(settings.mailcow_url).hostname or ''
    except Exception:
        name = ''
    if '.' not in name:
        name = socket.getfqdn()
    return name if '.' in name else 'localhost.localdomain'


def _fetch_certificate_sync(host: str) -> bytes:
    # DANE replaces PKIX validation for SMTP: the TLSA record, not a CA, says
    # which certificate is correct. So the handshake must accept any
    # certificate, and the comparison with the TLSA record is the check.
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with smtplib.SMTP(host, SMTP_PORT, local_hostname=_ehlo_name(),
                          timeout=SMTP_TIMEOUT) as smtp:
            smtp.ehlo()
            if not smtp.has_extn('starttls'):
                raise CertificateUnavailable('the server does not offer STARTTLS')
            smtp.starttls(context=context)
            certificate = smtp.sock.getpeercert(binary_form=True)
    except CertificateUnavailable:
        raise
    except (OSError, smtplib.SMTPException, ssl.SSLError) as e:
        raise CertificateUnavailable(str(e) or e.__class__.__name__) from e
    if not certificate:
        raise CertificateUnavailable('the server sent no certificate')
    return certificate


async def fetch_smtp_certificate(host: str) -> bytes:
    """DER certificate presented by host on port 25, cached for a few minutes.

    Raises CertificateUnavailable when it cannot be fetched.
    """
    key = host.lower().rstrip('.')
    cached = _cert_cache.get(key)
    if cached and time.monotonic() - cached[0] < CERT_CACHE_SECONDS:
        _, certificate, error = cached
        if certificate is None:
            raise CertificateUnavailable(error)
        return certificate
    try:
        certificate = await asyncio.to_thread(_fetch_certificate_sync, key)
    except CertificateUnavailable as e:
        logger.info(f"[DANE] Could not fetch the certificate of {key}: {e}")
        _cert_cache[key] = (time.monotonic(), None, str(e))
        raise
    _cert_cache[key] = (time.monotonic(), certificate, None)
    return certificate


def tlsa_association(certificate_der: bytes, selector: int, matching_type: int) -> Optional[bytes]:
    """The value a TLSA record with this selector/matching type should hold
    for the certificate, or None for combinations RFC 6698 does not define."""
    if selector == 0:
        data = certificate_der
    elif selector == 1:
        public_key = x509.load_der_x509_certificate(certificate_der).public_key()
        data = public_key.public_bytes(serialization.Encoding.DER,
                                       serialization.PublicFormat.SubjectPublicKeyInfo)
    else:
        return None
    if matching_type == 0:
        return data
    if matching_type == 1:
        return hashlib.sha256(data).digest()
    if matching_type == 2:
        return hashlib.sha512(data).digest()
    return None


def matches_certificate(record: Dict, certificate_der: bytes) -> bool:
    """True when a DANE-EE TLSA record (as built by check_tlsa_record) pins
    this certificate."""
    if record.get('usage') != USAGE_DANE_EE:
        return False
    try:
        expected = tlsa_association(certificate_der, record.get('selector'),
                                    record.get('matching_type'))
        published = bytes.fromhex(record.get('certificate') or '')
    except (ValueError, TypeError):
        return False
    return expected is not None and expected == published
