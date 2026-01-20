"""
Basic HTTP Authentication Middleware for FastAPI
Protects ALL endpoints when authentication is enabled
"""
import logging
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from fastapi import HTTPException, status
import secrets
import base64

from .config import settings

logger = logging.getLogger(__name__)


def verify_credentials(username: str, password: str) -> bool:
    """
    Verify HTTP Basic Auth credentials
    Returns True if valid, False otherwise
    """
    if not settings.auth_enabled:
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


class BasicAuthMiddleware(BaseHTTPMiddleware):
    """
    Middleware that enforces HTTP Basic Authentication on ALL requests
    when auth_enabled is True
    """
    
    async def dispatch(self, request: Request, call_next):
        # Skip authentication check if disabled
        if not settings.auth_enabled:
            return await call_next(request)
        
        # Allow access to login page, static files, health check, and info endpoint without authentication
        # Health check endpoint must be accessible for Docker health monitoring
        # Info endpoint is used to check if authentication is enabled
        path = request.url.path
        if path == "/login" or path.startswith("/static/") or path == "/api/health" or path == "/api/info":
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
            # Decode credentials
            encoded_credentials = authorization.split(" ")[1]
            decoded_credentials = base64.b64decode(encoded_credentials).decode("utf-8")
            username, password = decoded_credentials.split(":", 1)
            
            # Verify credentials
            if not verify_credentials(username, password):
                # Return 401 without WWW-Authenticate header to prevent browser popup
                return Response(
                    content="Incorrect username or password",
                    status_code=status.HTTP_401_UNAUTHORIZED,
                )
            
        except (ValueError, IndexError, UnicodeDecodeError) as e:
            logger.warning(f"Invalid authorization header: {e}")
            # Return 401 without WWW-Authenticate header to prevent browser popup
            return Response(
                content="Invalid authorization header",
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        
        # Credentials are valid, proceed with request
        return await call_next(request)

