"""
Session management for OAuth2 authentication
Uses HTTP-only cookies with server-side session storage
"""
import logging
import secrets
from typing import Dict, Optional, Any
from datetime import datetime, timedelta
from fastapi import Request, Response
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from .config import settings

logger = logging.getLogger(__name__)

# In-memory session store
# In production, consider using Redis for scalability
_session_store: Dict[str, Dict[str, Any]] = {}

# Session cookie name
SESSION_COOKIE_NAME = "session_id"


# Fallback key when SESSION_SECRET_KEY is unset — generated ONCE per process.
# (Generating a fresh key per call would sign and verify with different keys,
# silently invalidating every OAuth2 session.) Sessions still won't survive a
# restart without a configured key, matching the in-memory session store.
_generated_secret_key: str = ""


def get_session_secret_key() -> str:
    """Get the configured session secret key, or a stable per-process fallback"""
    global _generated_secret_key
    if not settings.session_secret_key:
        if not _generated_secret_key:
            logger.warning(
                "SESSION_SECRET_KEY not configured — using a temporary key. "
                "Sessions will not survive a restart; set SESSION_SECRET_KEY in production."
            )
            _generated_secret_key = secrets.token_urlsafe(32)
        return _generated_secret_key
    return settings.session_secret_key


def get_serializer() -> URLSafeTimedSerializer:
    """Get URL-safe timed serializer for signing session IDs"""
    return URLSafeTimedSerializer(get_session_secret_key())


def create_session(user_info: Dict[str, Any]) -> str:
    """
    Create a new session and return session ID
    
    Args:
        user_info: User information from OAuth2 provider
        
    Returns:
        Session ID (signed)
    """
    session_id = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(hours=settings.session_expiry_hours)
    
    session_data = {
        "user_info": user_info,
        "created_at": datetime.utcnow().isoformat(),
        "expires_at": expires_at.isoformat(),
    }
    
    _session_store[session_id] = session_data
    
    # Sign the session ID
    serializer = get_serializer()
    signed_session_id = serializer.dumps(session_id)
    
    logger.debug(f"Created session {session_id[:8]}... for user {user_info.get('email', 'unknown')}")
    
    return signed_session_id


def get_session(session_id: str) -> Optional[Dict[str, Any]]:
    """
    Get session data by session ID
    
    Args:
        session_id: Signed session ID from cookie
        
    Returns:
        Session data or None if invalid/expired
    """
    try:
        # Verify and unsign the session ID
        serializer = get_serializer()
        unsigned_session_id = serializer.loads(session_id, max_age=settings.session_expiry_hours * 3600)
    except (BadSignature, SignatureExpired) as e:
        logger.debug(f"Invalid session signature: {e}")
        return None
    
    # Get session from store
    session_data = _session_store.get(unsigned_session_id)
    if not session_data:
        logger.debug(f"Session {unsigned_session_id[:8]}... not found in store")
        return None
    
    # Check expiration
    expires_at = datetime.fromisoformat(session_data["expires_at"])
    if datetime.utcnow() > expires_at:
        logger.debug(f"Session {unsigned_session_id[:8]}... expired")
        del _session_store[unsigned_session_id]
        return None
    
    return session_data


def delete_session(session_id: str) -> bool:
    """
    Delete a session
    
    Args:
        session_id: Signed session ID from cookie
        
    Returns:
        True if session was deleted, False otherwise
    """
    try:
        serializer = get_serializer()
        unsigned_session_id = serializer.loads(session_id, max_age=settings.session_expiry_hours * 3600)
    except (BadSignature, SignatureExpired):
        return False
    
    if unsigned_session_id in _session_store:
        del _session_store[unsigned_session_id]
        logger.debug(f"Deleted session {unsigned_session_id[:8]}...")
        return True
    
    return False


def get_session_from_request(request: Request) -> Optional[Dict[str, Any]]:
    """
    Get session data from request cookie
    
    Args:
        request: FastAPI request object
        
    Returns:
        Session data or None if not found/invalid
    """
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_id:
        return None
    
    return get_session(session_id)


def set_session_cookie(response: Response, session_id: str) -> None:
    """
    Set session cookie in response
    
    Args:
        response: FastAPI response object
        session_id: Signed session ID
    """
    # Determine if we should use Secure flag (HTTPS)
    # Check if the app is likely running over HTTPS
    # In production, you should set this based on actual deployment
    secure = settings.debug is False  # Use Secure in production
    
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_id,
        max_age=settings.session_expiry_hours * 3600,
        httponly=True,
        secure=secure,
        samesite="lax",  # Lax for CSRF protection while allowing navigation
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    """
    Clear session cookie in response
    
    Args:
        response: FastAPI response object
    """
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
        httponly=True,
        secure=settings.debug is False,
        samesite="lax",
    )


def cleanup_expired_sessions() -> int:
    """
    Clean up expired sessions from store
    Call this periodically to prevent memory leaks
    
    Returns:
        Number of sessions cleaned up
    """
    now = datetime.utcnow()
    expired_sessions = []
    
    for session_id, session_data in _session_store.items():
        expires_at = datetime.fromisoformat(session_data["expires_at"])
        if now > expires_at:
            expired_sessions.append(session_id)
    
    for session_id in expired_sessions:
        del _session_store[session_id]
    
    if expired_sessions:
        logger.debug(f"Cleaned up {len(expired_sessions)} expired sessions")
    
    return len(expired_sessions)
