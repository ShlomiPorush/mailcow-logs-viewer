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
from .session import get_session_from_request, SESSION_COOKIE_NAME

logger = logging.getLogger(__name__)

# ── Brute-force protection (in-memory, per client IP) ──────────────────────
# After MAX_FAILURES failed Basic Auth attempts within WINDOW_SECONDS the
# client is rejected with 429 until enough failures age out of the window.
_AUTH_MAX_FAILURES = 10
_AUTH_WINDOW_SECONDS = 15 * 60
_auth_failures: Dict[str, Deque[float]] = {}


def _client_ip(request: Request) -> str:
    """Client IP for rate limiting; honors X-Forwarded-For behind the reverse proxy."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


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


def is_request_authenticated(request: Request) -> bool:
    """
    Check whether a request carries valid credentials (OAuth2 session or
    Basic Auth header). Used by public endpoints like /api/info to decide
    how much detail to expose. Returns True when authentication is disabled.
    """
    if not settings.is_authentication_enabled:
        return True

    if settings.is_oauth2_enabled and get_session_from_request(request):
        return True

    if settings.is_basic_auth_enabled:
        authorization = request.headers.get("Authorization", "")
        if authorization.startswith("Basic "):
            try:
                encoded = authorization.split(" ")[1]
                decoded = base64.b64decode(encoded).decode("utf-8")
                username, password = decoded.split(":", 1)
                return verify_credentials(username, password)
            except (ValueError, IndexError, UnicodeDecodeError):
                return False

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
        
        # Check OAuth2 session first (if enabled)
        if settings.is_oauth2_enabled:
            session_data = get_session_from_request(request)
            if session_data:
                # OAuth2 session is valid, proceed
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
        
        # Brute-force protection: reject before even checking credentials
        client_ip = _client_ip(request)
        if _is_rate_limited(client_ip):
            return Response(
                content="Too many failed login attempts. Try again later.",
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                headers={"Retry-After": str(_AUTH_WINDOW_SECONDS)},
            )

        try:
            # Decode credentials
            encoded_credentials = authorization.split(" ")[1]
            decoded_credentials = base64.b64decode(encoded_credentials).decode("utf-8")
            username, password = decoded_credentials.split(":", 1)

            # Verify credentials
            if not verify_credentials(username, password):
                _record_auth_failure(client_ip)
                # Return 401 without WWW-Authenticate header to prevent browser popup
                return Response(
                    content="Incorrect username or password",
                    status_code=status.HTTP_401_UNAUTHORIZED,
                )

        except (ValueError, IndexError, UnicodeDecodeError) as e:
            logger.warning(f"Invalid authorization header: {e}")
            _record_auth_failure(client_ip)
            # Return 401 without WWW-Authenticate header to prevent browser popup
            return Response(
                content="Invalid authorization header",
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        # Successful login clears the failure counter
        _clear_auth_failures(client_ip)
        
        # Credentials are valid, proceed with request
        return await call_next(request)

