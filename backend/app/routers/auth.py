"""
OAuth2/OIDC Authentication Router
Handles OAuth2 login flow, callbacks, logout, and status
"""
import logging
import secrets
from fastapi import APIRouter, Request, Response, HTTPException, status
from fastapi.responses import RedirectResponse
from typing import Dict, Any

from ..config import settings
from ..session import (
    create_session,
    get_session_from_request,
    delete_session,
    set_session_cookie,
    clear_session_cookie,
    SESSION_COOKIE_NAME,
)
from ..services.oauth2_client import oauth2_client, OAuth2ClientError

logger = logging.getLogger(__name__)

router = APIRouter()

# Store state tokens temporarily (in production, use Redis or database)
_state_store: Dict[str, str] = {}


@router.get("/auth/verify")
def verify_basic_auth():
    """
    Verify Basic Auth credentials.
    Not in public_paths: middleware validates credentials and returns 401 if invalid.
    Used by the login form to test username/password before redirecting.
    """
    return {"verified": True}


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
        
        # Generate CSRF state token
        state = secrets.token_urlsafe(32)
        _state_store[state] = "pending"
        
        # Get authorization URL
        auth_url = oauth2_client.get_authorization_url(state)
        
        logger.info(f"Redirecting to OAuth2 provider: {settings.oauth2_provider_name}")
        return RedirectResponse(url=auth_url)
        
    except OAuth2ClientError as e:
        logger.error(f"OAuth2 login error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"OAuth2 configuration error: {str(e)}"
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
    
    # Check for errors from provider
    if error:
        logger.warning(f"OAuth2 callback error: {error}")
        return RedirectResponse(
            url="/login?error=oauth2_error",
            status_code=status.HTTP_302_FOUND
        )
    
    # Validate state token (CSRF protection)
    if not state or state not in _state_store:
        logger.warning("Invalid or missing state token in OAuth2 callback")
        return RedirectResponse(
            url="/login?error=invalid_state",
            status_code=status.HTTP_302_FOUND
        )
    
    # Remove state token (one-time use)
    del _state_store[state]
    
    if not code:
        logger.warning("Missing authorization code in OAuth2 callback")
        return RedirectResponse(
            url="/login?error=missing_code",
            status_code=status.HTTP_302_FOUND
        )
    
    try:
        # Exchange code for token
        token_data = await oauth2_client.exchange_code_for_token(code)
        access_token = token_data.get('access_token')
        
        if not access_token:
            logger.error("No access token in token response")
            return RedirectResponse(
                url="/login?error=no_token",
                status_code=status.HTTP_302_FOUND
            )
        
        # Get user information
        user_info = await oauth2_client.get_user_info(access_token)
        
        # Create session
        session_id = create_session(user_info)
        
        # Create response with redirect
        response = RedirectResponse(
            url="/",
            status_code=status.HTTP_302_FOUND
        )
        
        # Set session cookie
        set_session_cookie(response, session_id)
        
        logger.info(f"OAuth2 login successful for user: {user_info.get('email', 'unknown')}")
        return response
        
    except OAuth2ClientError as e:
        logger.error(f"OAuth2 callback error: {e}")
        return RedirectResponse(
            url="/login?error=oauth2_error",
            status_code=status.HTTP_302_FOUND
        )
    except Exception as e:
        logger.error(f"Unexpected error during OAuth2 callback: {e}", exc_info=True)
        return RedirectResponse(
            url="/login?error=server_error",
            status_code=status.HTTP_302_FOUND
        )


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
    
    clear_session_cookie(response)
    
    logger.info("User logged out")
    return response


@router.get("/auth/status")
def auth_status(request: Request):
    """
    Check authentication status
    Returns current user info if authenticated
    """
    # Check OAuth2 session
    session_data = get_session_from_request(request)
    if session_data:
        return {
            "authenticated": True,
            "auth_type": "oauth2",
            "user": session_data.get("user_info", {}),
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
