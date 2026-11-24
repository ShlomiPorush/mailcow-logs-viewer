import ipaddress
from typing import Optional
from urllib.parse import urlsplit

from ..config import settings

LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

OFF = "off"
NO_SIGN_IN = "no_sign_in"
NO_URL = "no_url"
BAD_URL = "bad_url"


def is_loopback_host(host: str) -> bool:
    host = (host or "").lower().strip("[]")
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def normalize_base_url(value: str) -> Optional[str]:
    value = (value or "").strip()
    if not value or len(value) > 255:
        return None
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if not host or parts.username or parts.password or parts.query or parts.fragment:
        return None
    if parts.path not in ("", "/"):
        return None
    if scheme == "http":
        if not is_loopback_host(host):
            return None
    elif scheme != "https":
        return None
    shown_host = f"[{host}]" if ":" in host else host
    default = 443 if scheme == "https" else 80
    netloc = shown_host if port in (None, default) else f"{shown_host}:{port}"
    return f"{scheme}://{netloc}"


def problem() -> Optional[str]:
    if not settings.is_authentication_enabled:
        return NO_SIGN_IN
    if not settings.agent_access_enabled:
        return OFF
    if not (settings.agent_access_url or "").strip():
        return NO_URL
    if normalize_base_url(settings.agent_access_url) is None:
        return BAD_URL
    return None


def is_live() -> bool:
    return problem() is None


def issuer() -> str:
    base = normalize_base_url(settings.agent_access_url)
    if base is None:
        raise RuntimeError("agent access has no valid address")
    return base


def resource() -> str:
    return issuer() + "/mcp"


def api_resource() -> str:
    return issuer() + "/api"


def resources() -> tuple:
    return (resource(), api_resource())


def same_resource(given: str, expected: str) -> bool:
    if not given:
        return False
    try:
        a, b = urlsplit(given.strip()), urlsplit(expected)
        if a.fragment or a.query or a.username or a.password:
            return False
        return (a.scheme.lower(), (a.hostname or "").lower(), a.port, a.path.rstrip("/")) == \
               (b.scheme.lower(), (b.hostname or "").lower(), b.port, b.path.rstrip("/"))
    except ValueError:
        return False
