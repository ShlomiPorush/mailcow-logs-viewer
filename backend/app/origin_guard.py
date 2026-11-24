import logging
from typing import Optional, Tuple
from urllib.parse import urlsplit

from starlette.datastructures import Headers
from starlette.responses import JSONResponse

from .config import normalize_origin, settings

logger = logging.getLogger(__name__)

UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
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
    try:
        parts = urlsplit(source.strip())
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not parts.netloc:
        return None
    return _host_port(parts.netloc)


def is_same_origin(headers: Headers) -> bool:
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
    for candidate in (headers.get("host"), headers.get("x-forwarded-host")):
        if candidate and _host_port(candidate.split(",")[0]) == source_host:
            return True
    return False


def _describe(headers: Headers) -> str:
    source = headers.get("origin") or headers.get("referer") or ""
    return repr(source[:200])


class SameOriginGuardMiddleware:
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
                    await send({"type": "websocket.close", "code": 1008})
                return
        await self.app(scope, receive, send)
