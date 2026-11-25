import ipaddress
import re
import logging
import time
from threading import RLock
from collections import deque
from typing import Dict, Deque, Optional
from urllib.parse import quote, urlsplit, urlunsplit
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from fastapi import HTTPException, status
import secrets
import base64

from .config import settings
from .session import auth_generation, get_session_from_request, session_state
from .agent_access import live as agent_live
from .agent_access.context import agent_call

AGENT_PUBLIC_PATHS = frozenset({
    "/mcp",
    "/oauth/token",
    "/oauth/register",
    "/oauth/revoke",
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-protected-resource/mcp",
    "/.well-known/oauth-authorization-server",
})


AGENT_PUBLIC_REQUESTS = frozenset({("POST", "/oauth/device")})
SKILL_PREFIX = "/agents/skill"
MCP_NOTE_PATHS = frozenset({"/agents/mcp", "/agents/mcp/"})


def _is_agent_path(path: str) -> bool:
    return path == "/mcp" or path in MCP_NOTE_PATHS or path.startswith(("/oauth/", "/.well-known/oauth-", SKILL_PREFIX))


def _has_bearer(request: Request) -> bool:
    return any(part.lower() == "bearer"
               for value in request.headers.getlist("authorization")
               for part in re.split(r"[\s,]+", value))

logger = logging.getLogger(__name__)

_AUTH_MAX_FAILURES = 10
_AUTH_WINDOW_SECONDS = 15 * 60
_auth_failures: Dict[str, Deque[float]] = {}
_auth_lock = RLock()
_next_capacity_cleanup = 0.0


def _make_room_for_new_client() -> None:
    with _auth_lock:
        global _next_capacity_cleanup
        if len(_auth_failures) < settings.auth_max_failure_clients:
            return
        now = time.monotonic()
        if now >= _next_capacity_cleanup:
            cleanup_expired_auth_failures()
            _next_capacity_cleanup = now + 1.0
        while _auth_failures and len(_auth_failures) >= settings.auth_max_failure_clients:
            _auth_failures.pop(next(iter(_auth_failures)))


def _client_ip(request: Request) -> str:
    host = (request.client.host if request.client else None) or "unknown"
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host
    if address.version == 6:
        if address.ipv4_mapped:
            return str(address.ipv4_mapped)
        return str(ipaddress.ip_network(f"{address}/64", strict=False))
    return str(address)


def _is_rate_limited(ip: str) -> bool:
    with _auth_lock:
        failures = _auth_failures.get(ip)
        if not failures:
            return False
        cutoff = time.time() - _AUTH_WINDOW_SECONDS
        while failures and failures[0] < cutoff:
            failures.popleft()
        if not failures:
            _auth_failures.pop(ip, None)
            return False
        return len(failures) >= _AUTH_MAX_FAILURES


def cleanup_expired_auth_failures() -> None:
    with _auth_lock:
        for ip in list(_auth_failures):
            _is_rate_limited(ip)


def _record_auth_failure(ip: str) -> None:
    with _auth_lock:
        failures = _auth_failures.pop(ip, None)
        if failures is None:
            _make_room_for_new_client()
            failures = deque()
        _auth_failures[ip] = failures
        failures.append(time.time())
        while len(failures) > _AUTH_MAX_FAILURES:
            failures.popleft()
        if len(failures) == _AUTH_MAX_FAILURES:
            logger.warning(f"Auth rate limit reached for {ip} "
                           f"({_AUTH_MAX_FAILURES} failures in {_AUTH_WINDOW_SECONDS // 60}m)")


def _clear_auth_failures(ip: str) -> None:
    with _auth_lock:
        _auth_failures.pop(ip, None)


def verify_credentials(username: str, password: str) -> bool:
    if not settings.is_basic_auth_enabled:
        return True
    
    if not settings.auth_password:
        logger.error("Authentication is enabled but password is not configured")
        return False
    
    correct_username = secrets.compare_digest(
        username.encode("utf-8"),
        settings.auth_username.encode("utf-8")
    )
    correct_password = secrets.compare_digest(
        password.encode("utf-8"),
        settings.auth_password.encode("utf-8")
    )
    
    return correct_username and correct_password


def _authenticate_basic_request(request: Request) -> bool:
    with _auth_lock:
        authorization = request.headers.get("Authorization", "")
        if not authorization.startswith("Basic "):
            return False

        client_ip = _client_ip(request)
        if _is_rate_limited(client_ip):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed login attempts. Try again later.",
                headers={"Retry-After": str(_AUTH_WINDOW_SECONDS)},
            )

        try:
            decoded = base64.b64decode(authorization[6:]).decode("utf-8")
            username, password = decoded.split(":", 1)
        except (ValueError, UnicodeDecodeError):
            _record_auth_failure(client_ip)
            return False

        if not verify_credentials(username, password):
            _record_auth_failure(client_ip)
            return False

        _clear_auth_failures(client_ip)
        return True


def basic_credentials(request: Request) -> Optional[tuple]:
    authorization = request.headers.get("Authorization", "")
    if not authorization.startswith("Basic "):
        return None
    try:
        username, password = base64.b64decode(authorization[6:]).decode("utf-8").split(":", 1)
    except (ValueError, UnicodeDecodeError):
        return ("", "")
    return username, password


def sign_in_budget(request: Request) -> str:
    with _auth_lock:
        client_ip = _client_ip(request)
        if _is_rate_limited(client_ip):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed login attempts. Try again later.",
                headers={"Retry-After": str(_AUTH_WINDOW_SECONDS)},
            )
        return client_ip


def record_sign_in_failure(client_ip: str) -> None:
    _record_auth_failure(client_ip)


def clear_sign_in_failures(client_ip: str) -> None:
    _clear_auth_failures(client_ip)


def is_request_authenticated(request: Request) -> bool:
    if not settings.is_authentication_enabled:
        return True

    if get_session_from_request(request):
        return True

    if settings.is_basic_auth_enabled:
        return _authenticate_basic_request(request)

    return False


def safe_return_path(value: Optional[str]) -> str:
    if not value or len(value) > 2048 or not value.startswith("/") or value.startswith("//"):
        return "/"
    if "\\" in value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        return "/"
    parts = urlsplit(value)
    if parts.scheme or parts.netloc or not parts.path.startswith("/"):
        return "/"
    if parts.path == "/login" or parts.path.startswith(("/login/", "/api/", "/static/")):
        return "/"
    return urlunsplit(("", "", parts.path, parts.query, parts.fragment))


def _login_redirect(request: Request, reason: Optional[str] = None) -> Response:
    target = request.url.path + (f"?{request.url.query}" if request.url.query else "")
    query = []
    if reason:
        query.append("reason=" + quote(reason, safe=""))
    if safe_return_path(target) != "/":
        query.append("next=" + quote(target, safe=""))
    url = "/login" + ("?" + "&".join(query) if query else "")
    return RedirectResponse(
        url=url,
        status_code=status.HTTP_302_FOUND,
        headers={"Cache-Control": "no-store"},
    )


SESSION_ENDED_DETAIL = "Your session ended. Sign in again."


def session_ended_response(reason: str) -> JSONResponse:
    return JSONResponse(
        {"detail": SESSION_ENDED_DETAIL, "reason": reason},
        status_code=status.HTTP_401_UNAUTHORIZED,
        headers={"X-Session-End": reason, "Cache-Control": "no-store"},
    )


class BasicAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request.state.auth_generation = auth_generation()
        request.state.auth_admission = None
        path = request.url.path

        if _is_agent_path(path) and not agent_live.is_live():
            return Response(content="Not Found", status_code=status.HTTP_404_NOT_FOUND)

        if agent_call(request.scope) is not None:
            return await call_next(request)

        if path.startswith("/api/") and _has_bearer(request):
            from .agent_access import rest
            return await rest.handle(request)

        if not settings.is_authentication_enabled:
            request.state.auth_admission = ("open", None)
            return await call_next(request)

        if path in AGENT_PUBLIC_PATHS or (request.method, path) in AGENT_PUBLIC_REQUESTS:
            request.state.auth_admission = ("open", None)
            return await call_next(request)
        if request.method in ("GET", "HEAD") and (path == SKILL_PREFIX or path.startswith(SKILL_PREFIX + "/")
                                                  or path in MCP_NOTE_PATHS):
            request.state.auth_admission = ("open", None)
            return await call_next(request)

        public_paths = {
            "/login",
            "/api/health",
            "/api/info",
            "/api/auth/login",
            "/api/auth/callback",
            "/api/auth/provider-info",
            "/api/auth/session",
            "/api/auth/activity",
        }

        if path in public_paths or path.startswith("/static/"):
            request.state.auth_admission = ("open", None)
            return await call_next(request)
        
        state = session_state(request)
        if state.data is not None:
            request.state.auth_admission = ("session", state.key)
            return await call_next(request)

        if state.ended:
            if not path.startswith("/api/"):
                return _login_redirect(request, state.ended)
            if not request.headers.get("Authorization", "").startswith("Basic "):
                return session_ended_response(state.ended)
        
        if settings.is_oauth2_enabled and not settings.is_basic_auth_enabled:
            if path.startswith("/api/"):
                return Response(
                    content="Authentication required",
                    status_code=status.HTTP_401_UNAUTHORIZED,
                )
            return _login_redirect(request)
        
        if not settings.is_basic_auth_enabled:
            if path.startswith("/api/"):
                return Response(
                    content="Authentication required",
                    status_code=status.HTTP_401_UNAUTHORIZED,
                )
            return _login_redirect(request)

        if not settings.auth_password:
            logger.error("Authentication enabled but password not set")
            return Response(
                content="Authentication is enabled but password is not configured",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        authorization = request.headers.get("Authorization", "")
        
        if not path.startswith("/api/"):
            return _login_redirect(request)
        
        if not authorization.startswith("Basic "):
            # A WWW-Authenticate header here would make the browser show its own Basic Auth popup over the login form
            return Response(
                content="Authentication required",
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        
        try:
            authenticated = _authenticate_basic_request(request)
        except HTTPException as exc:
            return Response(
                content=exc.detail,
                status_code=exc.status_code,
                headers=exc.headers,
            )
        if not authenticated:
            return Response(
                content="Incorrect username or password",
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        
        request.state.auth_admission = ("basic", None)
        return await call_next(request)
