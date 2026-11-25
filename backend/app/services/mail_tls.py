import ipaddress
import logging
import ssl
from typing import Any, Optional

logger = logging.getLogger(__name__)

_MODES = {
    "": "false", "false": "false", "off": "false", "no": "false", "0": "false",
    "auto": "auto", "automatic": "auto",
    "true": "true", "on": "true", "yes": "true", "1": "true",
}

_warned = set()


def verify_mode(value: Any) -> Optional[str]:
    if value is None:
        return "false"
    if isinstance(value, bool):
        return "true" if value else "false"
    return _MODES.get(str(value).strip().lower())


def is_local_mail_host(host: Optional[str]) -> bool:
    name = (host or "").strip().strip("[]").rstrip(".").lower()
    if name == "localhost" or name.endswith(".localhost") or "." not in name:
        return True
    try:
        ipaddress.ip_address(name)
        return True
    except ValueError:
        return False


def mail_tls_context(host: Optional[str], mode: Any, setting_name: str) -> ssl.SSLContext:
    mode = verify_mode(mode) or "false"
    verify = mode == "true" or (mode == "auto" and not is_local_mail_host(host))
    if mode == "auto" and not verify and (setting_name, host) not in _warned:
        _warned.add((setting_name, host))
        logger.warning(
            "%s is auto and %s is a local name or IP address, so its TLS certificate is not checked. "
            "Set %s=true to check it.", setting_name, host, setting_name)
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


_SETTINGS_SECTION = {"SMTP_VERIFY_SSL": "SMTP", "DMARC_IMAP_VERIFY_SSL": "DMARC & TLS IMAP"}


def certificate_error_hint(error: BaseException, setting_name: str) -> Optional[str]:
    if not isinstance(error, ssl.SSLCertVerificationError):
        return None
    reason = getattr(error, "verify_message", None) or str(error)
    section = _SETTINGS_SECTION.get(setting_name, "")
    where = f" (Settings > {section}, or the environment)" if section else ""
    return (f"The server's TLS certificate is not trusted ({reason}). If this server uses a self-signed "
            f"certificate, set {setting_name} to Off{where}; otherwise check the host name and the certificate.")
