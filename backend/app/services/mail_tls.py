"""TLS context for the SMTP and IMAP connections that send a password.

Without an explicit context, smtplib and imaplib do not verify the server
certificate, so whoever can intercept the connection reads the password.
Every SMTP_SSL, starttls and IMAP4_SSL call takes its context from here.

The verify setting (SMTP_VERIFY_SSL, DMARC_IMAP_VERIFY_SSL):
  true   always verify the certificate chain and the host name
  false  never verify (a self-signed server the operator trusts)
  unset  verify a dotted host name (smtp.example.com); do not verify localhost,
         an IP address or a single-label name such as a Docker container name,
         which cannot carry a publicly trusted certificate and in a mailcow
         setup does not leave the host. A warning names the setting.
"""
import ipaddress
import logging
import ssl
from typing import Optional

logger = logging.getLogger(__name__)

# (setting, host) pairs already warned about, so a recurring sync warns once
_warned = set()


def is_local_mail_host(host: Optional[str]) -> bool:
    """localhost, an IP literal or a single-label name (a container name)."""
    name = (host or "").strip().strip("[]").rstrip(".").lower()
    if name == "localhost" or name.endswith(".localhost") or "." not in name:
        return True
    try:
        ipaddress.ip_address(name)
        return True
    except ValueError:
        return False


def mail_tls_context(host: Optional[str], verify: Optional[bool], setting_name: str) -> ssl.SSLContext:
    """A verifying context, unless the setting says false or is unset for a local host."""
    if verify is None:
        verify = not is_local_mail_host(host)
        if not verify and (setting_name, host) not in _warned:
            _warned.add((setting_name, host))
            logger.warning(
                "%s is not set and %s is a local name or IP address, so its TLS certificate is not verified. "
                "Set %s=true to verify it, or %s=false to silence this warning.",
                setting_name, host, setting_name, setting_name)
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def certificate_error_hint(error: BaseException, setting_name: str) -> Optional[str]:
    """A plain-language answer for a refused certificate, naming the setting; None for other errors."""
    if not isinstance(error, ssl.SSLCertVerificationError):
        return None
    reason = getattr(error, "verify_message", None) or str(error)
    section = _SETTINGS_SECTION.get(setting_name, "")
    where = f" (Settings - {section}, or the environment)" if section else ""
    return (f"The server's TLS certificate is not trusted ({reason}). If this server uses a self-signed "
            f"certificate, set {setting_name}=false{where}; otherwise check the host name and the certificate.")


# Where the setting lives on the Settings page
_SETTINGS_SECTION = {"SMTP_VERIFY_SSL": "SMTP", "DMARC_IMAP_VERIFY_SSL": "DMARC & TLS IMAP"}
