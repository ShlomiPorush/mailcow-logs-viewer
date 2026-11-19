"""
Session management for OAuth2 authentication
Uses HTTP-only cookies with server-side session storage

A session has two limits, whichever sign-in started it: the longest session
(session_expiry_hours, counted from sign-in) and, when it is on, sign-out after
inactivity (session_idle_timeout_minutes since the last interaction the browser
reported through POST /api/auth/activity). The server record alone decides:
the signed cookie only names the record.
"""
import logging
import math
import secrets
import time
from collections import OrderedDict
from threading import RLock
from typing import Callable, Dict, NamedTuple, Optional, Any, Tuple
from fastapi import Request, Response
from itsdangerous import URLSafeTimedSerializer, BadSignature

from . import config as _config
from .config import settings

logger = logging.getLogger(__name__)

# In-memory session store
# In production, consider using Redis for scalability
_session_store: Dict[str, Dict[str, Any]] = {}
_session_lock = RLock()
_next_capacity_cleanup = 0.0
# Advances whenever every session is revoked. Access derived from a session
# that outlives the request, such as a Live Logs stream, records it and ends
# when it changes.
_auth_generation = 0

# Why a session ended by a limit, kept for a while so the page can say so:
# key -> (reason, until). At most session_max_entries, the oldest dropped
# first; a session whose entry is gone is simply not signed in.
SESSION_EXPIRED = "session_expired"
SESSION_IDLE = "session_idle"
# The person's account changed or no longer gives access (user_access.py)
SESSION_ACCESS_CHANGED = "access_changed"
_TOMBSTONE_SECONDS = 600
_tombstones: "OrderedDict[str, Tuple[str, float]]" = OrderedDict()


def _now() -> float:
    """The clock every session limit is measured with (tests replace it)."""
    return time.time()


class SessionCapacityError(Exception):
    """No new sessions can be admitted without removing a live session."""


class SessionRevokedError(Exception):
    """Every session was revoked after the request was admitted, for example by
    a password change: a session issued now would outlive that change."""


class SessionState(NamedTuple):
    """A request's cookie session: its key and record while it is valid, or
    why it ended by a limit (None when there is no session to speak of)."""
    key: Optional[str]
    data: Optional[Dict[str, Any]]
    ended: Optional[str]


_NO_SESSION = SessionState(None, None, None)

# Session cookie name
SESSION_COOKIE_NAME = "session_id"


# Fallback key when SESSION_SECRET_KEY is unset - generated ONCE per process.
# (Generating a fresh key per call would sign and verify with different keys,
# silently invalidating every OAuth2 session.) Sessions still won't survive a
# restart without a configured key, matching the in-memory session store.
_generated_secret_key: str = ""


def get_session_secret_key() -> str:
    """Get the configured session secret key, or a stable per-process fallback"""
    with _session_lock:
        global _generated_secret_key
        if not settings.session_secret_key:
            if not _generated_secret_key:
                logger.warning(
                    "SESSION_SECRET_KEY not configured - using a temporary key. "
                    "Sessions will not survive a restart; set SESSION_SECRET_KEY in production."
                )
                _generated_secret_key = secrets.token_urlsafe(32)
            return _generated_secret_key
        return settings.session_secret_key


def get_serializer() -> URLSafeTimedSerializer:
    """Get URL-safe timed serializer for signing session IDs"""
    return URLSafeTimedSerializer(get_session_secret_key())


def _unsign(session_id: Optional[str]) -> Optional[str]:
    """The server-side key a signed cookie names, or None when the signature fails.

    No max_age: how long a session lasts is decided by its record only.
    """
    if not session_id:
        return None
    try:
        key = get_serializer().loads(session_id)
    except BadSignature as e:
        logger.debug(f"Invalid session signature: {e}")
        return None
    return key if isinstance(key, str) else None


# ── Limits ─────────────────────────────────────────────────────────────────

def _longest_hours(source=None) -> int:
    return max(1, int((source or settings).session_expiry_hours))


def _idle_seconds(source=None) -> int:
    return max(5, min(1440, int((source or settings).session_idle_timeout_minutes))) * 60


def _longest_seconds(record: Dict[str, Any]) -> int:
    """A shorter setting applies to open sessions; a longer one never goes past
    the length the session was issued with."""
    return min(int(record["issued_hours"]), _longest_hours()) * 3600


def _end_reason(record: Dict[str, Any], now: float) -> Optional[str]:
    """Why this session has ended under the settings in force, or None while
    it is valid. Called under _session_lock, which also holds the settings."""
    if now - record["login_at"] >= _longest_seconds(record):
        return SESSION_EXPIRED
    if settings.session_idle_enabled and now - record["active_at"] >= _idle_seconds():
        return SESSION_IDLE
    return None


def _end(key: str, reason: str, now: float) -> None:
    """Remove a session that a limit ended and remember why."""
    _session_store.pop(key, None)
    _tombstones.pop(key, None)
    _tombstones[key] = (reason, now + _TOMBSTONE_SECONDS)
    cap = max(0, int(settings.session_max_entries))
    while len(_tombstones) > cap:
        _tombstones.popitem(last=False)
    logger.debug(f"Session {key[:8]}... ended: {reason}")


def _tombstone(key: str, now: float) -> Optional[str]:
    entry = _tombstones.get(key)
    if entry is None:
        return None
    reason, until = entry
    if now >= until:
        _tombstones.pop(key, None)
        return None
    return reason


def _check(key: Optional[str]) -> SessionState:
    """The one validity check: the live record for this key, or why it ended.

    An ended session is removed at once; nothing brings it back.
    """
    if not key:
        return _NO_SESSION
    with _session_lock:
        now = _now()
        record = _session_store.get(key)
        if record is None:
            return SessionState(None, None, _tombstone(key, now))
        reason = _end_reason(record, now)
        if reason:
            _end(key, reason, now)
            return SessionState(None, None, reason)
        return SessionState(key, record, None)


def _publish_settings(new: Any, assign: Callable[[], None]) -> None:
    """Put new settings in force (config.reload_settings) under the session lock.

    Sessions that ended under the settings in force stay ended, whatever the
    new ones say, and so do sessions the new settings end: a shorter limit
    ends them now, so a later longer one cannot bring them back. When sign-out
    after inactivity is switched on, every session still valid starts its idle
    time now, not from its last activity under a policy that did not count it.
    """
    with _session_lock:
        now = _now()
        idle_was_on = bool(settings.session_idle_enabled)
        for key in list(_session_store):
            reason = _end_reason(_session_store[key], now)
            if reason:
                _end(key, reason, now)
        assign()
        if not idle_was_on and bool(getattr(new, "session_idle_enabled", False)):
            for record in _session_store.values():
                record["active_at"] = now
        for key in list(_session_store):
            reason = _end_reason(_session_store[key], now)
            if reason:
                _end(key, reason, now)


_config.set_settings_publisher(_publish_settings)


# ── Sessions ───────────────────────────────────────────────────────────────

def create_session(user_info: Dict[str, Any], *, generation: int,
                   principal: Optional[Dict[str, Any]] = None) -> str:
    """
    Create a new session and return session ID

    Args:
        user_info: User information from OAuth2 provider
        generation: auth_generation() when the request was admitted. A
            revocation since then refuses the session (SessionRevokedError).
        principal: who signed in, as user_access.py resolves it on every
            request; kept apart from user_info, which the provider fills.

    Returns:
        Session ID (signed)
    """
    with _session_lock:
        global _next_capacity_cleanup
        if generation != _auth_generation:
            raise SessionRevokedError("Sign-in settings changed after the request was admitted")
        if len(_session_store) >= settings.session_max_entries:
            now = time.monotonic()
            if now >= _next_capacity_cleanup:
                cleanup_expired_sessions()
                _next_capacity_cleanup = now + 1.0
            if len(_session_store) >= settings.session_max_entries:
                raise SessionCapacityError("Login capacity reached. Try again later.")
        session_id = secrets.token_urlsafe(32)
        now = _now()
        _session_store[session_id] = {
            "user_info": user_info,
            "login_at": now,
            "active_at": now,
            "issued_hours": _longest_hours(),
        }
        if principal is not None:
            _session_store[session_id]["principal"] = principal

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
    with _session_lock:
        return _check(_unsign(session_id)).data


def delete_session(session_id: str) -> bool:
    """
    Delete a session

    Args:
        session_id: Signed session ID from cookie

    Returns:
        True if session was deleted, False otherwise
    """
    with _session_lock:
        unsigned_session_id = _unsign(session_id)
        if unsigned_session_id is None:
            return False

        if unsigned_session_id in _session_store:
            _session_store.pop(unsigned_session_id, None)
            logger.debug(f"Deleted session {unsigned_session_id[:8]}...")
            return True

        return False


def revoke_all_sessions() -> int:
    """End every session, for example after the sign-in credentials changed.

    Returns the generation this revocation started. A session issued with it
    is refused once any later revocation has run.
    """
    return revoke_all_sessions_keeping(None, None)[0]


def revoke_all_sessions_keeping(keep: Optional[Dict[str, Any]], admitted: Optional[int]) -> Tuple[int, Optional[str]]:
    """revoke_all_sessions, keeping one session under a new key: the operator
    who saved a sign-in change stays signed in (routers/settings.py).

    Done in the same step as the revocation, so the kept session is never out
    of the store where a limit can end it. It is kept only while it is still
    there and valid, and only when no other revocation ran since its request
    was let in (`admitted`). It keeps its sign-in time, last activity and
    length, so saving never extends it. Returns the generation this revocation
    started and the kept session's signed ID, or None.
    """
    global _auth_generation
    with _session_lock:
        key = next((k for k, record in _session_store.items() if record is keep), None) if keep is not None else None
        if key is not None and (admitted != _auth_generation or _check(key).data is None):
            key = None
        count = len(_session_store)
        _session_store.clear()
        _auth_generation += 1
        generation = _auth_generation
        signed = None
        if key is not None:
            new_key = secrets.token_urlsafe(32)
            _session_store[new_key] = keep
            signed = get_serializer().dumps(new_key)
    logger.info(f"Revoked {count} session(s) after an authentication settings change")
    return generation, signed


def auth_generation() -> int:
    """The current value of the counter that revoke_all_sessions advances."""
    with _session_lock:
        return _auth_generation


def session_state(request: Request) -> SessionState:
    """The request's cookie session, checked against both limits."""
    return _check(_unsign(request.cookies.get(SESSION_COOKIE_NAME)))


def session_key_from_request(request: Request) -> Optional[str]:
    """The server-side key of the request's valid session, or None."""
    return session_state(request).key


def is_session_active(key: str) -> bool:
    """Whether the session with this server-side key exists and neither limit has ended it."""
    return _check(key).data is not None


def session_by_key(key: Optional[str]) -> SessionState:
    """The session with this server-side key, checked against both limits."""
    return _check(key)


def end_session(key: str, reason: str) -> None:
    """End one session now, remembering why, like a limit does."""
    with _session_lock:
        if key in _session_store:
            _end(key, reason, _now())


def end_sessions_where(match: Callable[[Dict[str, Any]], bool], reason: str) -> int:
    """End every session whose record matches, for example all of one user's."""
    with _session_lock:
        now = _now()
        keys = [k for k, record in _session_store.items() if match(record)]
        for key in keys:
            _end(key, reason, now)
        return len(keys)


def get_session_from_request(request: Request) -> Optional[Dict[str, Any]]:
    """
    Get session data from request cookie

    Args:
        request: FastAPI request object

    Returns:
        Session data or None if not found/invalid
    """
    return session_state(request).data


def _limits(record: Dict[str, Any], now: float) -> Dict[str, Any]:
    longest_left = record["login_at"] + _longest_seconds(record) - now
    idle_on = bool(settings.session_idle_enabled)
    idle = _idle_seconds() if idle_on else None
    return {
        "longest_seconds_left": max(0, math.ceil(longest_left)),
        "idle_enabled": idle_on,
        "idle_timeout_seconds": idle,
        "idle_seconds_left": max(0, math.ceil(record["active_at"] + idle - now)) if idle_on else None,
    }


def session_limits(request: Request) -> Optional[Dict[str, Any]]:
    """How long the request's cookie session has left under each limit, or
    None without a valid one. Reading it never counts as activity."""
    with _session_lock:
        state = session_state(request)
        return _limits(state.data, _now()) if state.data is not None else None


def record_activity(request: Request) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """The person used the page: restart the idle time of the request's own
    cookie session. Returns its limits, or None and why it ended (None when
    there is no session). An ended session stays ended."""
    with _session_lock:
        state = session_state(request)
        if state.data is None:
            return None, state.ended
        now = _now()
        state.data["active_at"] = now
        return _limits(state.data, now), None


def is_secure_request(request: Optional[Request]) -> bool:
    """Whether this request reached us over HTTPS.

    The Secure flag has to follow the actual deployment: a Secure cookie is
    silently dropped by the browser on plain HTTP, which would lock out every
    self-hosted instance served over http:// on a LAN. Behind a reverse proxy
    the scheme arrives in X-Forwarded-Proto.
    """
    if request is None:
        # No request context: assume HTTPS unless the app runs in debug mode.
        return settings.debug is False
    forwarded = request.headers.get("x-forwarded-proto", "")
    if forwarded:
        return forwarded.split(",")[0].strip().lower() == "https"
    return request.url.scheme == "https"


def _cookie_max_age(session_id: str) -> int:
    """Seconds until the session reaches the length it was issued with: the
    full length at sign-in, the time left when a session is re-issued."""
    with _session_lock:
        record = _session_store.get(_unsign(session_id) or "")
        if record is None:
            return _longest_hours() * 3600
        return max(1, math.ceil(record["login_at"] + int(record["issued_hours"]) * 3600 - _now()))


def set_session_cookie(
    response: Response, session_id: str, request: Optional[Request] = None
) -> None:
    """
    Set session cookie in response

    Args:
        response: FastAPI response object
        session_id: Signed session ID
        request: Incoming request, used to decide on the Secure flag
    """
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_id,
        max_age=_cookie_max_age(session_id),
        httponly=True,
        secure=is_secure_request(request),
        samesite="lax",  # Lax for CSRF protection while allowing navigation
        path="/",
    )


def clear_session_cookie(response: Response, request: Optional[Request] = None) -> None:
    """
    Clear session cookie in response

    Args:
        response: FastAPI response object
        request: Incoming request, used to decide on the Secure flag
    """
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
        httponly=True,
        secure=is_secure_request(request),
        samesite="lax",
    )


def cleanup_expired_sessions() -> int:
    """
    Clean up expired sessions from store
    Call this periodically to prevent memory leaks

    Returns:
        Number of sessions cleaned up
    """
    with _session_lock:
        now = _now()
        ended = 0
        for key in list(_session_store):
            reason = _end_reason(_session_store[key], now)
            if reason:
                _end(key, reason, now)
                ended += 1
        for key in [k for k, (_reason, until) in _tombstones.items() if now >= until]:
            _tombstones.pop(key, None)

        if ended:
            logger.debug(f"Cleaned up {ended} expired sessions")

        return ended
