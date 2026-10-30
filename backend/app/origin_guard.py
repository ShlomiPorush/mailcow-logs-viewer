"""
Reject state-changing requests and WebSocket upgrades that another site started.

The web interface is served from the same origin as the API, so its own writes
always carry an Origin (or Referer) naming this host. A page on another site
can still make the operator's browser send a request here, for example an
auto-submitted text/plain form POST to a mailcow write route. That needs no
CORS and, with authentication off (the default), no credentials either. This
guard is active whether or not authentication is enabled.

Only host[:port] is compared, never the scheme: behind the documented TLS
reverse proxy the app sees plain HTTP while the browser sends an https Origin.
Requests with neither Origin nor Referer (curl, scripts, API clients) pass;
browsers always send Origin on these requests.
"""
import logging
from typing import Optional, Tuple
from urllib.parse import urlsplit

from starlette.datastructures import Headers
from starlette.responses import JSONResponse

from .config import normalize_origin, settings

logger = logging.getLogger(__name__)

UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
# Default ports are equivalent because the scheme is not compared
_DEFAULT_PORTS = (None, 80, 443)


def _host_port(netloc: str) -> Optional[Tuple[str, Optional[int]]]:
    try:
        parts = urlsplit("//" + netloc.strip())
        hostname, port = parts.hostname, parts.port
    except ValueError:
        return None
    if not hostname or parts.username or parts.password:
        return None
    return hostname.lower(), (None if port in _DEFAULT_PORTS else port)


def _source_host(source: str) -> Optional[Tuple[str, Optional[int]]]:
    """host[:port] of an Origin or Referer value; None for 'null' or anything unparsable."""
    try:
        parts = urlsplit(source.strip())
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not parts.netloc:
        return None
    return _host_port(parts.netloc)


def is_same_origin(headers: Headers) -> bool:
    """Whether the request came from this app's own pages (or from no browser page at all)."""
    source = headers.get("origin")
    if source is None:
        source = headers.get("referer")
    if source is None:
        return True

    origin = normalize_origin(source)
    if origin and origin in settings.cors_allowed_origins_list:
        return True

    source_host = _source_host(source)
    if source_host is None:
        return False
    # A proxy that rewrites Host usually passes the browser's in X-Forwarded-Host
    for candidate in (headers.get("host"), headers.get("x-forwarded-host")):
        if candidate and _host_port(candidate.split(",")[0]) == source_host:
            return True
    return False


def _describe(headers: Headers) -> str:
    source = headers.get("origin") or headers.get("referer") or ""
    return repr(source[:200])


class SameOriginGuardMiddleware:
    """Pure ASGI middleware (BaseHTTPMiddleware breaks the /ws/raw-logs upgrade)."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope["method"] in UNSAFE_METHODS:
            headers = Headers(scope=scope)
            if not is_same_origin(headers):
                logger.warning("Rejected a cross-site %s %s from %s", scope["method"], scope["path"], _describe(headers))
                response = JSONResponse(
                    status_code=403,
                    content={"detail": "This request came from another site and was rejected."},
                )
                await response(scope, receive, send)
                return
        elif scope["type"] == "websocket":
            headers = Headers(scope=scope)
            if not is_same_origin(headers):
                logger.warning("Rejected a cross-site WebSocket to %s from %s", scope["path"], _describe(headers))
                message = await receive()
                if message["type"] == "websocket.connect":
                    # Closing before accept answers the handshake with HTTP 403
                    await send({"type": "websocket.close", "code": 1008})
                return
        await self.app(scope, receive, send)
