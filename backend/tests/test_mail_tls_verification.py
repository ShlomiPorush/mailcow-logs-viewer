"""SMTP and IMAP clients verify the server certificate before they send a password.

Without an ssl context, smtplib and imaplib fall back to an unverified one, so
anyone able to intercept the connection could present any certificate and read
the SMTP or IMAP password. The servers here run on loopback with a self-signed
certificate for an unrelated name, the way an interceptor would; nothing leaves
the machine (a dotted name is pointed at loopback by patching getaddrinfo).

SMTP_VERIFY_SSL / DMARC_IMAP_VERIFY_SSL: false (also unset, the default, so an
upgrade changes nothing) does not check, auto checks dotted host names and skips
localhost, IP addresses and single-label names such as Docker container names,
true always checks.
"""
import base64
import datetime
import logging
import socket
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app import config as cfg
from app.services import connection_test
from app.services.dmarc_imap_service import DMARCImapService
from app.services.smtp_service import SmtpService

PASSWORD = "Dummy-Secret-PW-42"
DOTTED = "mail.example.com"
UNSET = object()  # keep the setting's default


def _server_context(tmp_path_factory):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rogue.invalid")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("rogue.invalid")]), False)
            .sign(key, hashes.SHA256()))
    d = tmp_path_factory.mktemp("tls")
    (d / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (d / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(d / "c.pem", d / "k.pem")
    return ctx


class RogueServers:
    """SMTPS, SMTP with STARTTLS and IMAPS listeners that record any password they get."""

    def __init__(self, sctx):
        self.sctx = sctx
        self.captured = []
        self.ports = {kind: self._serve(kind) for kind in ("smtps", "starttls", "imaps")}

    def got_password(self):
        return any(PASSWORD in c for c in self.captured)

    def _serve(self, kind):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        s.listen(8)

        def loop():
            while True:
                c, _ = s.accept()
                threading.Thread(target=self._handle, args=(kind, c), daemon=True).start()

        threading.Thread(target=loop, daemon=True).start()
        return s.getsockname()[1]

    def _handle(self, kind, conn):
        try:
            conn.settimeout(10)
            if kind in ("smtps", "imaps"):
                conn = self.sctx.wrap_socket(conn, server_side=True)
            if kind == "imaps":
                self._imap(conn)
            else:
                self._smtp(conn, starttls=(kind == "starttls"))
        except (OSError, ssl.SSLError):
            pass  # the client refused the certificate
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _smtp(self, conn, starttls, greet=True):
        f = conn.makefile("rwb")

        def w(line):
            f.write((line + "\r\n").encode())
            f.flush()

        if greet:
            w("220 rogue.invalid ESMTP")
        for raw in iter(f.readline, b""):
            line = raw.decode(errors="replace").strip()
            cmd = line.upper()
            if cmd.startswith(("EHLO", "HELO")):
                w("250-rogue.invalid")
                w("250-AUTH PLAIN LOGIN")
                w("250 STARTTLS" if starttls else "250 OK")
            elif cmd.startswith("STARTTLS"):
                w("220 go ahead")
                return self._smtp(self.sctx.wrap_socket(conn, server_side=True), starttls=False, greet=False)
            elif cmd.startswith("AUTH PLAIN"):
                self.captured.append(base64.b64decode(line.split()[2]).decode(errors="replace"))
                w("535 5.7.8 rejected")
            elif cmd.startswith("QUIT"):
                w("221 bye")
                return
            else:
                w("502 no")

    def _imap(self, conn):
        f = conn.makefile("rwb")

        def w(line):
            f.write((line + "\r\n").encode())
            f.flush()

        w("* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] ready")
        for raw in iter(f.readline, b""):
            parts = raw.decode(errors="replace").strip().split(" ", 2)
            tag, cmd = parts[0], (parts[1].upper() if len(parts) > 1 else "")
            if cmd == "CAPABILITY":
                w("* CAPABILITY IMAP4rev1 AUTH=PLAIN")
                w(f"{tag} OK done")
            elif cmd == "LOGIN":
                self.captured.append(parts[2] if len(parts) > 2 else "")
                w(f"{tag} NO rejected")
            elif cmd == "LOGOUT":
                w("* BYE")
                w(f"{tag} OK")
                return
            else:
                w(f"{tag} BAD")


@pytest.fixture(scope="module")
def rogue(tmp_path_factory):
    return RogueServers(_server_context(tmp_path_factory))


@pytest.fixture
def mail(rogue, monkeypatch):
    """Point SMTP and IMAP at the rogue servers; returns a function to set the host and verify mode."""
    rogue.captured.clear()
    real_getaddrinfo = socket.getaddrinfo

    def getaddrinfo(host, *args, **kwargs):
        return real_getaddrinfo("127.0.0.1" if host == DOTTED else host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)

    def configure(host, verify=UNSET, smtp_mode="starttls"):
        values = {
            "smtp_enabled": True, "smtp_host": host, "smtp_user": "notify@example.com",
            "smtp_password": PASSWORD, "smtp_from": "notify@example.com", "smtp_relay_mode": False,
            "admin_email": "admin@example.com",
            "smtp_port": rogue.ports[smtp_mode], "smtp_use_ssl": smtp_mode == "smtps",
            "smtp_use_tls": smtp_mode == "starttls",
            "dmarc_imap_host": host, "dmarc_imap_port": rogue.ports["imaps"], "dmarc_imap_use_ssl": True,
            "dmarc_imap_user": "dmarc@example.com", "dmarc_imap_password": PASSWORD,
        }
        if verify is not UNSET:
            values.update({"smtp_verify_ssl": verify, "dmarc_imap_verify_ssl": verify})
        monkeypatch.setattr(cfg.settings, "_inner", cfg.settings._inner.model_copy(update=values))

    return configure


# What a verifying client must do: refuse the certificate before any password is sent

@pytest.mark.parametrize("host,verify", [("localhost", "true"), (DOTTED, "true"), (DOTTED, "auto")])
@pytest.mark.parametrize("smtp_mode", ["smtps", "starttls"])
def test_send_email_refuses_an_untrusted_certificate(rogue, mail, host, verify, smtp_mode):
    mail(host, verify, smtp_mode)
    assert SmtpService().send_email("admin@example.com", "subject", "text") is False
    assert not rogue.got_password()


@pytest.mark.parametrize("host,verify", [("localhost", "true"), (DOTTED, "auto")])
def test_smtp_connection_test_refuses_and_names_the_setting(rogue, mail, host, verify):
    mail(host, verify, "starttls")
    result = connection_test.test_smtp_connection()
    assert result["success"] is False
    assert not rogue.got_password()
    assert any("SMTP_VERIFY_SSL" in line for line in result["logs"])


@pytest.mark.parametrize("host,verify", [("localhost", "true"), (DOTTED, "auto")])
def test_imap_connection_test_refuses_and_names_the_setting(rogue, mail, host, verify):
    mail(host, verify)
    result = connection_test.test_imap_connection()
    assert result["success"] is False
    assert not rogue.got_password()
    assert any("DMARC_IMAP_VERIFY_SSL" in line for line in result["logs"])


@pytest.mark.parametrize("host,verify", [("localhost", "true"), (DOTTED, "auto")])
def test_dmarc_imap_sync_refuses_and_names_the_setting(rogue, mail, host, verify):
    mail(host, verify)
    with pytest.raises(Exception) as exc:
        DMARCImapService().connect()
    assert "DMARC_IMAP_VERIFY_SSL" in str(exc.value)
    assert not rogue.got_password()


# Off (the default) and auto with a local name do not check: the password still goes out

@pytest.mark.parametrize("host,verify", [
    (DOTTED, UNSET), ("localhost", UNSET), (DOTTED, "false"), ("localhost", "auto"), ("127.0.0.1", "auto"),
])
def test_unverified_by_default_when_off_or_auto_with_a_local_name(rogue, mail, host, verify):
    mail(host, verify, "smtps")
    SmtpService().send_email("admin@example.com", "subject", "text")
    with pytest.raises(Exception):
        DMARCImapService().connect()  # the rogue server rejects the login
    assert sum(PASSWORD in c for c in rogue.captured) == 2


def test_auto_mode_warns_and_names_the_setting(rogue, mail, caplog):
    from app.services import mail_tls
    mail_tls._warned.clear()  # the warning is given once per host
    mail("localhost", "auto", "smtps")
    with caplog.at_level(logging.WARNING):
        SmtpService().send_email("admin@example.com", "subject", "text")
    assert any("SMTP_VERIFY_SSL" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize("host,mode,verified", [
    ("smtp.example.com", "auto", True),
    ("smtp.example.com.", "auto", True),
    ("localhost", "auto", False),
    ("LOCALHOST", "auto", False),
    ("127.0.0.1", "auto", False),
    ("::1", "auto", False),
    ("[2001:db8::1]", "auto", False),
    ("postfix-mailcow", "auto", False),
    ("localhost", "true", True),
    ("smtp.example.com", "true", True),
    ("smtp.example.com", "false", False),
    ("smtp.example.com", "", False),
    ("smtp.example.com", None, False),
])
def test_mail_tls_context_modes(host, mode, verified):
    from app.services.mail_tls import mail_tls_context
    ctx = mail_tls_context(host, mode, "SMTP_VERIFY_SSL")
    assert (ctx.verify_mode == ssl.CERT_REQUIRED) is verified
    assert ctx.check_hostname is verified


@pytest.mark.parametrize("key", ["smtp_verify_ssl", "dmarc_imap_verify_ssl"])
def test_verify_settings_default_to_off_and_are_editable(key, monkeypatch):
    from pydantic import ValidationError
    assert key in cfg.EDITABLE_SETTING_KEYS
    monkeypatch.delenv(key.upper(), raising=False)
    assert getattr(cfg.Settings(), key) == "false"
    for raw, expected in [("true", "true"), ("TRUE", "true"), ("Auto", "auto"), ("false", "false"),
                          ("off", "false"), ("", "false")]:
        monkeypatch.setenv(key.upper(), raw)
        assert getattr(cfg.Settings(), key) == expected
    monkeypatch.setenv(key.upper(), "maybe")
    with pytest.raises(ValidationError):
        cfg.Settings()
