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
import concurrent.futures
import functools
import hashlib
import logging
import smtplib
import socket
import ssl
import threading
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)

SMTP_PORT = 25
SMTP_TIMEOUT = 10            # seconds for one step: connect, one read, the TLS handshake
SMTP_TOTAL_SECONDS = 20      # the whole probe, however slowly the server answers
PROBE_GRACE_SECONDS = 5      # extra wait for name lookups, which the budget cannot cut
MAX_REPLY_LINES = 64         # lines in one SMTP reply; smtplib alone accepts any number
MAX_ADDRESSES = 2            # addresses tried per MX host
MAX_PROBES = 10              # probes running at once, each on its own thread
CERT_CACHE_SECONDS = 600     # many domains share one MX; probe it once per run

USAGE_DANE_TA = 2
USAGE_DANE_EE = 3

_cert_cache: Dict[str, Tuple[float, Optional[bytes], Optional[str]]] = {}

# The probes block, so they run on threads, but not on the default executor:
# ingestion, the protection rules and name lookups share that one. A probe is
# only started when a thread is free for it, so nothing queues behind a slow MX.
_executor = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_PROBES,
                                                  thread_name_prefix='dane-probe')
_running = 0
_running_lock = threading.Lock()


class CertificateUnavailable(Exception):
    """The certificate could not be fetched (port 25 blocked, no STARTTLS...)."""


class ProbeBusy(CertificateUnavailable):
    """Too many probes are running in this app. Says nothing about the host,
    so it is not cached."""


@functools.lru_cache(maxsize=1)
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


def _pick_addresses(infos: List[tuple]) -> List[tuple]:
    """At most MAX_ADDRESSES distinct addresses, one per address family
    first, so a host whose IPv6 is broken is still reached over IPv4."""
    unique = []
    for info in infos:
        if all(info[4] != seen[4] for seen in unique):
            unique.append(info)
    picked = []
    for info in unique:
        if all(info[0] != seen[0] for seen in picked):
            picked.append(info)
    for info in unique:
        if info not in picked:
            picked.append(info)
    return picked[:MAX_ADDRESSES]


class _BoundedSMTP(smtplib.SMTP):
    """smtplib.SMTP whose every network step shares one wall-clock deadline.

    smtplib's own timeout applies to each socket call, its reply reader takes
    any number of lines, and a buffered readline keeps reading while bytes
    trickle in, so a server could hold the probe for as long as it likes.
    Here the time left is checked before every connect, send and recv, and
    one reply may have at most MAX_REPLY_LINES lines.
    """

    def __init__(self, host: str, deadline: float):
        self._deadline = deadline
        self._buffer = b''
        self._buffer_sock = None
        super().__init__(host, SMTP_PORT, local_hostname=_ehlo_name(), timeout=SMTP_TIMEOUT)

    def step_timeout(self) -> float:
        """Timeout for the next network step; raises once the budget is spent."""
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            self.close()
            raise smtplib.SMTPServerDisconnected('the server took too long to answer')
        return min(SMTP_TIMEOUT, remaining)

    def _get_socket(self, host, port, timeout):
        # socket.create_connection would try every published address with a
        # full timeout each
        last_error: OSError = OSError(f'no address found for {host}')
        for family, socktype, proto, _, address in _pick_addresses(
                socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)):
            step = self.step_timeout()
            sock = socket.socket(family, socktype, proto)
            try:
                sock.settimeout(step)
                sock.connect(address)
                return sock
            except OSError as e:
                sock.close()
                last_error = e
        raise last_error

    def send(self, s):
        if self.sock:
            self.sock.settimeout(self.step_timeout())
        super().send(s)

    def _readline(self) -> bytes:
        """One line of at most smtplib._MAXLINE + 1 bytes, read in recv
        calls that each get only the time left."""
        if self._buffer_sock is not self.sock:
            self._buffer, self._buffer_sock = b'', self.sock
        limit = smtplib._MAXLINE + 1
        while True:
            end = self._buffer.find(b'\n', 0, limit)
            if end >= 0:
                line, self._buffer = self._buffer[:end + 1], self._buffer[end + 1:]
                return line
            if len(self._buffer) >= limit:
                return self._buffer[:limit]
            self.sock.settimeout(self.step_timeout())
            chunk = self.sock.recv(4096)
            if not chunk:
                line, self._buffer = self._buffer, b''
                return line
            self._buffer += chunk

    def getreply(self):
        # smtplib.SMTP.getreply, reading through _readline and with a line cap
        resp = []
        while True:
            try:
                line = self._readline()
            except OSError as e:
                self.close()
                raise smtplib.SMTPServerDisconnected('Connection unexpectedly closed: ' + str(e))
            if not line:
                self.close()
                raise smtplib.SMTPServerDisconnected('Connection unexpectedly closed')
            if len(line) > smtplib._MAXLINE:
                self.close()
                raise smtplib.SMTPResponseException(500, 'Line too long.')
            if len(resp) >= MAX_REPLY_LINES:
                self.close()
                raise smtplib.SMTPResponseException(500, 'Reply has too many lines.')
            resp.append(line[4:].strip(b' \t\r\n'))
            try:
                errcode = int(line[:3])
            except ValueError:
                errcode = -1
                break
            if line[3:4] != b'-':
                break
        return errcode, b'\n'.join(resp)


def _fetch_certificate_sync(host: str, deadline: float) -> bytes:
    # DANE replaces PKIX validation for SMTP: the TLSA record, not a CA, says
    # which certificate is correct. So the handshake must accept any
    # certificate, and the comparison with the TLSA record is the check.
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    smtp = None
    try:
        smtp = _BoundedSMTP(host, deadline)
        smtp.ehlo()
        if not smtp.has_extn('starttls'):
            raise CertificateUnavailable('the server does not offer STARTTLS')
        code, _ = smtp.docmd('STARTTLS')
        if code != 220:
            raise CertificateUnavailable(f'the server refused STARTTLS ({code})')
        # The handshake runs under one socket timeout, so give it only the
        # time left. Only the certificate is needed: no QUIT, just close.
        smtp.sock.settimeout(smtp.step_timeout())
        smtp.sock = context.wrap_socket(smtp.sock, server_hostname=host)
        certificate = smtp.sock.getpeercert(binary_form=True)
    except CertificateUnavailable:
        raise
    except (OSError, smtplib.SMTPException, ssl.SSLError) as e:
        raise CertificateUnavailable(str(e) or e.__class__.__name__) from e
    finally:
        if smtp is not None:
            smtp.close()
    if not certificate:
        raise CertificateUnavailable('the server sent no certificate')
    return certificate


def _probe_finished(_future) -> None:
    global _running
    with _running_lock:
        _running -= 1


async def _probe(host: str) -> bytes:
    """Run one probe on the probe executor, or raise ProbeBusy when every
    probe thread is taken. The slot is freed when the thread finishes, not
    when the caller stops waiting."""
    global _running
    with _running_lock:
        if _running >= MAX_PROBES:
            raise ProbeBusy('too many certificate checks are running')
        _running += 1
    try:
        future = _executor.submit(_fetch_certificate_sync, host,
                                  time.monotonic() + SMTP_TOTAL_SECONDS)
    except BaseException:
        _probe_finished(None)
        raise
    future.add_done_callback(_probe_finished)
    try:
        return await asyncio.wait_for(asyncio.wrap_future(future),
                                      SMTP_TOTAL_SECONDS + PROBE_GRACE_SECONDS)
    except asyncio.TimeoutError:
        raise CertificateUnavailable('the server took too long to answer') from None


async def fetch_smtp_certificate(host: str) -> bytes:
    """DER certificate presented by host on port 25, cached for a few minutes.

    Raises CertificateUnavailable when it cannot be fetched, and its subclass
    ProbeBusy when no probe could be started.
    """
    key = host.lower().rstrip('.')
    cached = _cert_cache.get(key)
    if cached and time.monotonic() - cached[0] < CERT_CACHE_SECONDS:
        _, certificate, error = cached
        if certificate is None:
            raise CertificateUnavailable(error)
        return certificate
    try:
        certificate = await _probe(key)
    except ProbeBusy:
        raise
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
