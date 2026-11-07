"""The DANE port 25 probe against a loopback SMTP server, and the limits that
keep a domain's MX hosts from holding it: one deadline for the whole probe,
however the server paces its replies; a cap on lines per reply; its own
threads, never the default executor that ingestion and name lookups share;
and a cap on how many MX hosts one check probes. Nothing leaves 127.0.0.1."""
import asyncio
import datetime
import socket
import ssl
import threading
import time
from types import SimpleNamespace

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

import dns.rcode
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.routers import domains
from app.services import dane
from app.services.dns_resolver import DnssecAnswer

STEP = 1.0      # per-step timeout in these tests
BUDGET = 1.5    # whole-probe budget in these tests
SLACK = 1.0     # scheduling allowance on a busy CI runner


# --- a loopback SMTP server ---------------------------------------------------

class FakeMX:
    """Threaded SMTP server on 127.0.0.1. `script(conn, stop)` handles each
    connection; `stop` is set when the test ends so no script runs on."""

    def __init__(self, script):
        self.script = script
        self.stop = threading.Event()
        self.listener = socket.create_server(('127.0.0.1', 0))
        self.listener.settimeout(0.05)
        self.port = self.listener.getsockname()[1]
        self.connections = []
        self.threads = [threading.Thread(target=self._accept, daemon=True)]
        self.threads[0].start()

    def _accept(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except (socket.timeout, OSError):
                continue
            self.connections.append(conn)
            worker = threading.Thread(target=self._run, args=(conn,), daemon=True)
            self.threads.append(worker)
            worker.start()

    def _run(self, conn):
        try:
            self.script(conn, self.stop)
        except (OSError, ssl.SSLError):
            pass

    def close(self):
        self.stop.set()
        for conn in self.connections:
            try:
                conn.close()
            except OSError:
                pass
        self.listener.close()
        for thread in self.threads:
            thread.join(5)


@pytest.fixture
def fake_mx(monkeypatch):
    servers = []
    monkeypatch.setattr(dane, 'SMTP_TIMEOUT', STEP)
    monkeypatch.setattr(dane, 'SMTP_TOTAL_SECONDS', BUDGET)
    monkeypatch.setattr(dane, '_ehlo_name', lambda: 'logs.example.test')
    monkeypatch.setattr(dane, '_cert_cache', {})

    def start(script):
        server = FakeMX(script)
        servers.append(server)
        monkeypatch.setattr(dane, 'SMTP_PORT', server.port)
        return server

    try:
        yield start
    finally:
        for server in servers:
            server.close()


def read_line(conn):
    line = b''
    while not line.endswith(b'\n'):
        byte = conn.recv(1)
        if not byte:
            raise OSError('client closed')
        line += byte
    return line


def _certificate(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'mail.example.test')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    cert_file, key_file = tmp_path / 'cert.pem', tmp_path / 'key.pem'
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    return context, cert.public_bytes(serialization.Encoding.DER)


def smtp_server(tls_context, greeting=b'220 mail.example.test ready\r\n', starttls_delay=0.0,
                stall_handshake=False):
    """A server that greets, answers EHLO with a multi-line reply offering
    STARTTLS, and then completes (or stalls) the TLS handshake."""
    def script(conn, stop):
        conn.sendall(greeting)
        read_line(conn)                                   # EHLO
        conn.sendall(b'250-mail.example.test\r\n250-PIPELINING\r\n'
                     b'250-SIZE 10240000\r\n250-8BITMIME\r\n250 STARTTLS\r\n')
        read_line(conn)                                   # STARTTLS
        stop.wait(starttls_delay)
        conn.sendall(b'220 2.0.0 Ready to start TLS\r\n')
        if stall_handshake:
            stop.wait()
            return
        tls = tls_context.wrap_socket(conn, server_side=True)
        stop.wait()
        tls.close()
    return script


def run_probe_in_thread(host='127.0.0.1'):
    """Run the blocking probe on a plain thread; (thread, outcome, elapsed)."""
    outcome = {}

    def target():
        started = time.monotonic()
        try:
            outcome['certificate'] = dane._fetch_certificate_sync(host, time.monotonic() + BUDGET)
        except Exception as e:
            outcome['error'] = e
        outcome['elapsed'] = time.monotonic() - started

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(BUDGET + SLACK)
    return thread, outcome


# --- the probe ----------------------------------------------------------------

def test_normal_server_gives_its_certificate(fake_mx, tmp_path):
    context, der = _certificate(tmp_path)
    fake_mx(smtp_server(context, greeting=b'220-mail.example.test\r\n220-welcome\r\n220 ready\r\n'))
    thread, outcome = run_probe_in_thread()
    assert not thread.is_alive()
    assert outcome.get('certificate') == der, outcome.get('error')


def test_greeting_dripped_forever_ends_at_the_budget(fake_mx):
    def drip_lines(conn, stop):
        while not stop.wait(0.05):
            conn.sendall(b'220-still greeting\r\n')

    fake_mx(drip_lines)
    thread, outcome = run_probe_in_thread()
    assert not thread.is_alive(), 'the probe thread is still held by the server'
    assert isinstance(outcome['error'], dane.CertificateUnavailable)
    assert outcome['elapsed'] < BUDGET + SLACK


def test_bytes_dripped_without_a_line_end_end_at_the_budget(fake_mx):
    # One readline would keep reading as long as bytes keep coming
    def drip_bytes(conn, stop):
        conn.sendall(b'220 ')
        while not stop.wait(0.05):
            conn.sendall(b'x')

    fake_mx(drip_bytes)
    thread, outcome = run_probe_in_thread()
    assert not thread.is_alive(), 'the probe thread is still held by the server'
    assert isinstance(outcome['error'], dane.CertificateUnavailable)


def test_reply_with_too_many_lines_is_refused(fake_mx, tmp_path):
    # Otherwise a normal server: without the cap the probe would succeed
    context, _ = _certificate(tmp_path)
    greeting = b'220-hello\r\n' * 100 + b'220 ready\r\n'
    fake_mx(smtp_server(context, greeting=greeting))
    thread, outcome = run_probe_in_thread()
    assert not thread.is_alive()
    assert isinstance(outcome.get('error'), dane.CertificateUnavailable)
    assert 'too many lines' in str(outcome['error'])


def test_handshake_gets_only_the_time_left(fake_mx, monkeypatch, tmp_path):
    # Each step stays under the per-step timeout; the handshake then stalls.
    # The probe must end at the budget, not one more full step later.
    monkeypatch.setattr(dane, 'SMTP_TIMEOUT', 2.0)
    budget = 2.5
    monkeypatch.setattr(dane, 'SMTP_TOTAL_SECONDS', budget)
    context, _ = _certificate(tmp_path)
    fake_mx(smtp_server(context, starttls_delay=1.8, stall_handshake=True))
    started = time.monotonic()
    with pytest.raises(dane.CertificateUnavailable):
        dane._fetch_certificate_sync('127.0.0.1', time.monotonic() + budget)
    assert time.monotonic() - started < budget + 0.6


def test_async_probe_returns_and_frees_its_thread(fake_mx):
    def drip_lines(conn, stop):
        while not stop.wait(0.05):
            conn.sendall(b'220-still greeting\r\n')

    fake_mx(drip_lines)
    outcome = {}

    def check():
        try:
            asyncio.run(dane.fetch_smtp_certificate('127.0.0.1'))
        except Exception as e:
            outcome['error'] = e

    # On its own thread, so a probe that never ends fails the test instead of
    # hanging it; the server stops when the test ends
    caller = threading.Thread(target=check, daemon=True)
    caller.start()
    caller.join(BUDGET + SLACK)
    assert not caller.is_alive(), 'the check is still waiting for the server'
    assert isinstance(outcome.get('error'), dane.CertificateUnavailable)
    deadline = time.monotonic() + SLACK
    while dane._running and time.monotonic() < deadline:
        time.sleep(0.01)
    assert dane._running == 0


def test_probe_runs_on_its_own_threads(monkeypatch):
    names = []

    def fake_sync(host, *args):
        names.append(threading.current_thread().name)
        return b'cert'

    monkeypatch.setattr(dane, '_fetch_certificate_sync', fake_sync)
    monkeypatch.setattr(dane, '_cert_cache', {})
    assert asyncio.run(dane.fetch_smtp_certificate('mail.example.test')) == b'cert'
    assert names and names[0].startswith('dane-probe')


def test_probes_beyond_the_thread_limit_are_refused_and_not_cached(monkeypatch):
    release = threading.Event()
    calls = []

    def blocking_sync(host, deadline):
        calls.append(host)
        if host != 'late.example.test':
            release.wait(10)
        return b'cert'

    monkeypatch.setattr(dane, '_fetch_certificate_sync', blocking_sync)
    monkeypatch.setattr(dane, '_cert_cache', {})

    async def scenario():
        held = [asyncio.create_task(dane.fetch_smtp_certificate(f'mx{i}.example.test'))
                for i in range(dane.MAX_PROBES)]
        started = time.monotonic()
        while len(calls) < dane.MAX_PROBES:
            assert time.monotonic() - started < 5, 'the probes did not all start'
            await asyncio.sleep(0.01)
        with pytest.raises(dane.ProbeBusy):
            await dane.fetch_smtp_certificate('late.example.test')
        release.set()
        assert await asyncio.gather(*held) == [b'cert'] * dane.MAX_PROBES
        # the refusal said nothing about the host, so it was not cached
        return await dane.fetch_smtp_certificate('late.example.test')

    try:
        assert asyncio.run(scenario()) == b'cert'
    finally:
        release.set()
    assert 'late.example.test' in calls


def test_addresses_tried_are_capped_one_per_family_first():
    def info(family, address):
        return (family, socket.SOCK_STREAM, 6, '', address)

    v6a = info(socket.AF_INET6, ('2001:db8::1', 25, 0, 0))
    v6b = info(socket.AF_INET6, ('2001:db8::2', 25, 0, 0))
    v4 = info(socket.AF_INET, ('192.0.2.1', 25))
    assert dane._pick_addresses([v6a, v6a, v6b, v4]) == [v6a, v4]
    assert dane._pick_addresses([v4, v4]) == [v4]


# --- how many MX hosts one check probes -------------------------------------------

def _mx_zone(count, tlsa_hosts=None):
    hosts = [f'mx{i:02d}.example.test' for i in range(1, count + 1)]
    records = {('example.test', 'MX'): DnssecAnswer(dns.rcode.NOERROR, True, [
        SimpleNamespace(exchange=h + '.', preference=10 * i) for i, h in enumerate(hosts, 1)])}
    tlsa = SimpleNamespace(usage=3, selector=1, mtype=1, cert=b'\x01' * 32)
    for host in (hosts if tlsa_hosts is None else tlsa_hosts):
        records[(f'_25._tcp.{host}', 'TLSA')] = DnssecAnswer(dns.rcode.NOERROR, True, [tlsa])
        records[(host, 'A')] = DnssecAnswer(dns.rcode.NOERROR, True,
                                            [SimpleNamespace(address='192.0.2.10')])
    return hosts, records


def _check(monkeypatch, records):
    probes = []

    async def resolve(name, rtype='A', timeout=5, checking_disabled=False):
        return records.get((name, rtype), DnssecAnswer(dns.rcode.NXDOMAIN, True, []))

    async def fetch(host):
        probes.append(host)
        return b'not the pinned certificate'

    monkeypatch.setattr(domains, 'resolve_dnssec_with_fallback', resolve)
    monkeypatch.setattr(domains, '_fetch_mx_certificate', fetch)
    return asyncio.run(domains.check_tlsa_record('example.test')), probes


def test_only_the_most_preferred_mx_hosts_are_probed(monkeypatch):
    hosts, records = _mx_zone(domains.MAX_DANE_MX_HOSTS + 2)
    # the last host by name is the most preferred, so it must be checked
    records[('example.test', 'MX')].records[-1].preference = 1
    result, probes = _check(monkeypatch, records)
    assert len(probes) == domains.MAX_DANE_MX_HOSTS
    assert hosts[-1] in probes
    assert result['not_checked'] == hosts[-3:-1]
    assert result['mx_hosts'] == hosts
    assert (f'Not checked: {hosts[-3]}, {hosts[-2]}. Only the first '
            f'{domains.MAX_DANE_MX_HOSTS} mail servers are checked.') in result['warnings']
    assert not any(h in w for h in hosts[-3:-1] for w in result['warnings'] if w.startswith('No TLSA'))


def test_tlsa_only_on_unchecked_hosts_is_not_a_removal(monkeypatch):
    count = domains.MAX_DANE_MX_HOSTS + 1
    hosts, records = _mx_zone(count, tlsa_hosts=[f'mx{count:02d}.example.test'])
    result, probes = _check(monkeypatch, records)
    assert probes == []
    assert result['record'] is None
    assert result['not_checked'] == [hosts[-1]]
    assert any(w.startswith('Not checked:') for w in result['warnings'])

    class Prev:
        spf_check = dkim_check = dmarc_check = mta_sts_check = tls_rpt_check = dnssec_check = None
        tlsa_check = {'status': 'success', 'record': '3 1 1 ' + '01' * 32, 'certificate_mismatch': []}

    assert domains.detect_dns_changes(Prev(), {'tlsa': result}) == []
