"""
OAuth2/OIDC Authentication Router
Handles OAuth2 login flow, callbacks, logout, and status
"""
import base64
import binascii
import logging
import secrets
import re
import time
from fastapi import APIRouter, Request, Response, HTTPException, status
from fastapi.responses import JSONResponse, RedirectResponse
from typing import Dict, Any

from ..config import settings
from ..session import (
    create_session,
    SessionCapacityError,
    get_session_from_request,
    delete_session,
    set_session_cookie,
    clear_session_cookie,
    SESSION_COOKIE_NAME,
    is_secure_request,
)
from ..services.oauth2_client import oauth2_client, OAuth2ClientError

logger = logging.getLogger(__name__)

router = APIRouter()

# The application runs one worker; pending authorizations expire after ten minutes.
OAUTH_STATE_TTL = 600
MAX_PENDING_OAUTH_STATES = 1024
OAUTH_COOKIE_PREFIX = "oauth_state_"
_state_store: Dict[str, tuple[str, float]] = {}


def _cleanup_oauth_states() -> None:
    now = time.monotonic()
    for token, (_, expires_at) in list(_state_store.items()):
        if expires_at <= now:
            del _state_store[token]


def _oauth_redirect(url: str, state: str, request: Request) -> RedirectResponse:
    response = RedirectResponse(url=url, status_code=status.HTTP_302_FOUND)
    response.delete_cookie(
        key=OAUTH_COOKIE_PREFIX + state, path="/", httponly=True,
        secure=is_secure_request(request), samesite="lax",
    )
    return response


@router.get("/auth/verify")
def verify_basic_auth():
    """
    Verify Basic Auth credentials.
    Not in public_paths: middleware validates credentials and returns 401 if invalid.
    Used by the login form to test username/password before redirecting.
    """
    return {"verified": True}


@router.post("/auth/session")
def create_basic_auth_session(request: Request):
    """
    Exchange verified Basic Auth credentials for a session cookie.

    Not in public_paths, so the middleware has already checked the
    Authorization header by the time this runs: reaching this function means
    the credentials are valid. The password is never stored in the browser -
    the login form sends it once, here, and from then on the HttpOnly session
    cookie authenticates every request.
    """
    if not settings.is_basic_auth_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Basic authentication is not enabled",
        )

    username = settings.auth_username
    authorization = request.headers.get("Authorization", "")
    if authorization.startswith("Basic "):
        try:
            decoded = base64.b64decode(authorization[6:]).decode("utf-8")
            username = decoded.split(":", 1)[0] or username
        except (binascii.Error, UnicodeDecodeError, ValueError):
            pass

    try:
        session_id = create_session({"username": username, "auth_method": "basic"})
    except SessionCapacityError:
        raise HTTPException(
            status_code=503, detail="Login capacity reached. Try again later.",
            headers={"Retry-After": "60"},
        )
    response = JSONResponse(content={"authenticated": True, "auth_type": "basic"})
    set_session_cookie(response, session_id, request)
    logger.info("Basic Auth session created")
    return response


@router.get("/auth/provider-info")
def get_provider_info():
    """Get authentication provider information for frontend"""
    return {
        "oauth2_enabled": settings.is_oauth2_enabled,
        "basic_auth_enabled": settings.is_basic_auth_enabled,
        "provider_name": settings.oauth2_provider_name if settings.is_oauth2_enabled else None,
    }


@router.get("/auth/login")
async def oauth2_login(request: Request):
    """
    Initiate OAuth2 login flow
    Redirects user to OAuth2 provider
    """
    if not settings.is_oauth2_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OAuth2 authentication is not enabled"
        )
    
    if not oauth2_client.is_configured():
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="OAuth2 client is not properly configured"
        )
    
    try:
        # Initialize client (perform discovery if needed)
        await oauth2_client.initialize()
        
        _cleanup_oauth_states()
        if len(_state_store) >= MAX_PENDING_OAUTH_STATES:
            raise HTTPException(status_code=503, detail="Too many pending logins. Try again later.")

        state = secrets.token_urlsafe(32)
        # Independent random nonce, never an OAuth client secret or user password.
        browser_nonce = secrets.token_urlsafe(32)
        auth_url = oauth2_client.get_authorization_url(state)
        response = RedirectResponse(url=auth_url)
        # A separate cookie per flow permits concurrent logins in different tabs.
        # Lax allows the provider's top-level GET callback; no Domain scopes it
        # to this host. Follow the existing session cookie's HTTPS policy.
        response.set_cookie(
            key=OAUTH_COOKIE_PREFIX + state, value=browser_nonce,
            max_age=OAUTH_STATE_TTL, httponly=True,
            secure=is_secure_request(request), samesite="lax", path="/",
        )
        _state_store[state] = (browser_nonce, time.monotonic() + OAUTH_STATE_TTL)
        logger.info(f"Redirecting to OAuth2 provider: {settings.oauth2_provider_name}")
        return response
        
    except HTTPException:
        raise
    except OAuth2ClientError as e:
        logger.error(f"OAuth2 login error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="OAuth2 is not configured correctly - see the application logs"
        )
    except Exception as e:
        logger.error(f"Unexpected error during OAuth2 login: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during OAuth2 login"
        )


@router.get("/auth/callback")
async def oauth2_callback(
    request: Request,
    code: str = None,
    state: str = None,
    error: str = None
):
    """
    Handle OAuth2 callback from provider
    """
    if not settings.is_oauth2_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OAuth2 authentication is not enabled"
        )
    
    _cleanup_oauth_states()
    pending = _state_store.get(state) if state else None
    browser_nonce = request.cookies.get(OAUTH_COOKIE_PREFIX + state, "") if pending else ""
    if (not pending or not re.fullmatch(r"[A-Za-z0-9_-]{43}", browser_nonce)
            or not secrets.compare_digest(pending[0], browser_nonce)):
        logger.warning("Invalid, expired or unbound state in OAuth2 callback")
        return RedirectResponse(url="/login?error=invalid_state", status_code=302)

    # Consume before any await, including on provider errors or missing codes.
    # A callback from another browser must not consume the owner's state.
    del _state_store[state]
    if error:
        logger.warning("OAuth2 provider declined authorization")
        return _oauth_redirect("/login?error=oauth2_error", state, request)

    if not code:
        logger.warning("Missing authorization code in OAuth2 callback")
        return _oauth_redirect("/login?error=missing_code", state, request)
    
    try:
        # Exchange code for token
        token_data = await oauth2_client.exchange_code_for_token(code)
        access_token = token_data.get('access_token')
        
        if not access_token:
            logger.error("No access token in token response")
            return _oauth_redirect("/login?error=no_token", state, request)
        
        # Get user information
        user_info = await oauth2_client.get_user_info(access_token)
        
        # Create session
        session_id = create_session(user_info)
        
        # Create response with redirect
        response = _oauth_redirect("/", state, request)
        
        # Set session cookie
        set_session_cookie(response, session_id, request)
        
        logger.info(f"OAuth2 login successful for user: {user_info.get('email', 'unknown')}")
        return response
        
    except SessionCapacityError:
        return _oauth_redirect("/login?error=session_capacity", state, request)
    except OAuth2ClientError as e:
        logger.error(f"OAuth2 callback error: {e}")
        return _oauth_redirect("/login?error=oauth2_error", state, request)
    except Exception as e:
        logger.error(f"Unexpected error during OAuth2 callback: {e}", exc_info=True)
        return _oauth_redirect("/login?error=server_error", state, request)


@router.get("/auth/logout")
def oauth2_logout(request: Request):
    """
    Logout and clear session
    """
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    
    if session_id:
        delete_session(session_id)
    
    response = RedirectResponse(
        url="/login",
        status_code=status.HTTP_302_FOUND
    )
    
    clear_session_cookie(response, request)
    
    logger.info("User logged out")
    return response


@router.get("/auth/status")
def auth_status(request: Request):
    """
    Check authentication status
    Returns current user info if authenticated
    """
    # Session cookie (OAuth2 login, or Basic Auth exchanged for a session)
    session_data = get_session_from_request(request)
    if session_data:
        user_info = session_data.get("user_info", {})
        return {
            "authenticated": True,
            "auth_type": user_info.get("auth_method", "oauth2"),
            "user": user_info,
        }
    
    # Check Basic Auth (if enabled)
    if settings.is_basic_auth_enabled:
        authorization = request.headers.get("Authorization", "")
        if authorization.startswith("Basic "):
            # Basic Auth is present, but we don't return user info for Basic Auth
            # The middleware handles validation
            return {
                "authenticated": True,
                "auth_type": "basic",
                "user": None,  # Basic Auth doesn't provide user info
            }
    
    return {
        "authenticated": False,
        "auth_type": None,
        "user": None,
    }
