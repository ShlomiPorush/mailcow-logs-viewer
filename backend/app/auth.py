"""
Authentication Middleware for FastAPI
Supports both OAuth2 (session cookies) and Basic Auth
Protects ALL endpoints when authentication is enabled
"""
import logging
import time
from collections import deque
from typing import Dict, Deque
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from fastapi import HTTPException, status
import secrets
import base64

from .config import settings
from .session import get_session_from_request

logger = logging.getLogger(__name__)

# ── Brute-force protection (in-memory, per client IP) ──────────────────────
# After MAX_FAILURES failed Basic Auth attempts within WINDOW_SECONDS the
# client is rejected with 429 until enough failures age out of the window.
_AUTH_MAX_FAILURES = 10
_AUTH_WINDOW_SECONDS = 15 * 60
_auth_failures: Dict[str, Deque[float]] = {}


def _client_ip(request: Request) -> str:
    """Use the transport peer or the client resolved by Uvicorn's trusted proxies.

    Uvicorn applies FORWARDED_ALLOW_IPS before the request reaches us. Reading
    X-Forwarded-For again would bypass that trust boundary and let a direct
    caller (or a forged prefix before a real proxy chain) choose its counter.
    """
    return (request.client.host if request.client else None) or "unknown"


def _is_rate_limited(ip: str) -> bool:
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
    """Reclaim idle client counters, retaining every unexpired failure."""
    for ip in list(_auth_failures):
        _is_rate_limited(ip)


def _record_auth_failure(ip: str) -> None:
    failures = _auth_failures.setdefault(ip, deque())
    failures.append(time.time())
    # Bound total memory: drop oldest entries beyond the threshold
    while len(failures) > _AUTH_MAX_FAILURES:
        failures.popleft()
    if len(failures) == _AUTH_MAX_FAILURES:
        logger.warning(f"Auth rate limit reached for {ip} "
                       f"({_AUTH_MAX_FAILURES} failures in {_AUTH_WINDOW_SECONDS // 60}m)")


def _clear_auth_failures(ip: str) -> None:
    _auth_failures.pop(ip, None)


def verify_credentials(username: str, password: str) -> bool:
    """
    Verify HTTP Basic Auth credentials
    Returns True if valid, False otherwise
    """
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
    """Check Basic credentials through the same failure budget on every route.

    Public routes may use the result to select their response fields, so they
    must count failed guesses too. A blocked attempt must not check credentials
    or reveal whether they were correct. Requests without Basic credentials do
    not consume the budget, keeping public login information available.
    """
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


def is_request_authenticated(request: Request) -> bool:
    """
    Check whether a request carries valid credentials (session cookie or
    Basic Auth header). Used by public endpoints like /api/info to decide
    how much detail to expose. Returns True when authentication is disabled.
    """
    if not settings.is_authentication_enabled:
        return True

    if get_session_from_request(request):
        return True

    if settings.is_basic_auth_enabled:
        return _authenticate_basic_request(request)

    return False


class BasicAuthMiddleware(BaseHTTPMiddleware):
    """
    Middleware that enforces authentication on ALL requests
    Supports both OAuth2 (session cookies) and Basic Auth
    when auth_enabled is True
    """
    
    async def dispatch(self, request: Request, call_next):
        # Skip authentication check if disabled
        if not settings.is_authentication_enabled:
            return await call_next(request)
        
        path = request.url.path
        
        # Allow access to login page, static files, health check, info endpoint, and auth endpoints without authentication
        # Health check endpoint must be accessible for Docker health monitoring
        # Info endpoint is used to check if authentication is enabled
        # Auth endpoints handle their own authentication
        public_paths = [
            "/login",
            "/static/",
            "/api/health",
            "/api/info",
            "/api/auth/login",
            "/api/auth/callback",
            "/api/auth/provider-info",
        ]
        
        if any(path == p or path.startswith(p) for p in public_paths):
            return await call_next(request)
        
        # A valid session cookie is accepted for both authentication methods:
        # OAuth2 logins get one from the callback, Basic Auth logins from
        # POST /api/auth/session. The cookie is HttpOnly, so no script in the
        # page can read it - which is why the password is never stored client
        # side any more.
        session_data = get_session_from_request(request)
        if session_data:
            return await call_next(request)
        
        # If OAuth2 is enabled but Basic Auth is not, require OAuth2
        if settings.is_oauth2_enabled and not settings.is_basic_auth_enabled:
            # OAuth2 only mode - redirect to login or return 401
            if path.startswith("/api/"):
                return Response(
                    content="Authentication required",
                    status_code=status.HTTP_401_UNAUTHORIZED,
                )
            # For frontend routes, allow through (frontend will redirect)
            return await call_next(request)
        
        # Fall back to Basic Auth (if enabled)
        if not settings.is_basic_auth_enabled:
            # No authentication method available
            if path.startswith("/api/"):
                return Response(
                    content="Authentication required",
                    status_code=status.HTTP_401_UNAUTHORIZED,
                )
            return await call_next(request)
        
        # Check if password is configured
        if not settings.auth_password:
            logger.error("Authentication enabled but password not set")
            return Response(
                content="Authentication is enabled but password is not configured",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        # Extract credentials from Authorization header
        authorization = request.headers.get("Authorization", "")
        
        # For frontend routes (not API), allow access without Authorization header
        # The frontend JavaScript will handle authentication and redirect if needed
        # This enables clean URLs like /dashboard, /messages, /dmarc etc.
        if not path.startswith("/api/"):
            return await call_next(request)
        
        # For all other paths (API endpoints), require authentication
        if not authorization.startswith("Basic "):
            # Return 401 without WWW-Authenticate header to prevent browser popup
            # The frontend login form will handle authentication
            return Response(
                content="Authentication required",
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        
        try:
            authenticated = _authenticate_basic_request(request)
        except HTTPException as exc:
            # Middleware runs outside FastAPI's HTTPException handler.
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
        
        # Credentials are valid, proceed with request
        return await call_next(request)
