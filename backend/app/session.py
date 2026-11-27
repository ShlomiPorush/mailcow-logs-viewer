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

_session_store: Dict[str, Dict[str, Any]] = {}
_session_lock = RLock()
_next_capacity_cleanup = 0.0
_auth_generation = 0

SESSION_EXPIRED = "session_expired"
SESSION_IDLE = "session_idle"
SESSION_ACCESS_CHANGED = "access_changed"
_TOMBSTONE_SECONDS = 600
_tombstones: "OrderedDict[str, Tuple[str, float]]" = OrderedDict()


def _now() -> float:
    return time.time()


class SessionCapacityError(Exception):
    pass


class SessionRevokedError(Exception):
    pass


class SessionState(NamedTuple):
    key: Optional[str]
    data: Optional[Dict[str, Any]]
    ended: Optional[str]


_NO_SESSION = SessionState(None, None, None)

SESSION_COOKIE_NAME = "session_id"


_generated_secret_key: str = ""


def get_session_secret_key() -> str:
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
    return URLSafeTimedSerializer(get_session_secret_key())


def _unsign(session_id: Optional[str]) -> Optional[str]:
    if not session_id:
        return None
    try:
        key = get_serializer().loads(session_id)
    except BadSignature as e:
        logger.debug(f"Invalid session signature: {e}")
        return None
    return key if isinstance(key, str) else None


def _longest_hours(source=None) -> int:
    return max(1, int((source or settings).session_expiry_hours))


def _idle_seconds(source=None) -> int:
    return max(5, min(1440, int((source or settings).session_idle_timeout_minutes))) * 60


def _longest_seconds(record: Dict[str, Any]) -> int:
    return min(int(record["issued_hours"]), _longest_hours()) * 3600


def _end_reason(record: Dict[str, Any], now: float) -> Optional[str]:
    if now - record["login_at"] >= _longest_seconds(record):
        return SESSION_EXPIRED
    if settings.session_idle_enabled and now - record["active_at"] >= _idle_seconds():
        return SESSION_IDLE
    return None


def _end(key: str, reason: str, now: float) -> None:
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


def create_session(user_info: Dict[str, Any], *, generation: int, principal: Dict[str, Any]) -> str:
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
            "principal": principal,
        }

        serializer = get_serializer()
        signed_session_id = serializer.dumps(session_id)

        logger.debug(f"Created session {session_id[:8]}... for user {user_info.get('email', 'unknown')}")

        return signed_session_id


def get_session(session_id: str) -> Optional[Dict[str, Any]]:
    with _session_lock:
        return _check(_unsign(session_id)).data


def delete_session(session_id: str) -> bool:
    with _session_lock:
        unsigned_session_id = _unsign(session_id)
        if unsigned_session_id is None:
            return False

        if unsigned_session_id in _session_store:
            _session_store.pop(unsigned_session_id, None)
            logger.debug(f"Deleted session {unsigned_session_id[:8]}...")
            return True

        return False


def revoke_all_sessions_keeping(keep: Optional[Dict[str, Any]], admitted: Optional[int]) -> Tuple[int, Optional[str]]:
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
    with _session_lock:
        return _auth_generation


def session_state(request: Request) -> SessionState:
    return _check(_unsign(request.cookies.get(SESSION_COOKIE_NAME)))


def session_key_from_request(request: Request) -> Optional[str]:
    return session_state(request).key


def is_session_active(key: str) -> bool:
    return _check(key).data is not None


def session_by_key(key: Optional[str]) -> SessionState:
    return _check(key)


def end_session(key: str, reason: str) -> None:
    with _session_lock:
        if key in _session_store:
            _end(key, reason, _now())


def end_sessions_where(match: Callable[[Dict[str, Any]], bool], reason: str) -> int:
    with _session_lock:
        now = _now()
        keys = [k for k, record in _session_store.items() if match(record)]
        for key in keys:
            _end(key, reason, now)
        return len(keys)


def get_session_from_request(request: Request) -> Optional[Dict[str, Any]]:
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
    with _session_lock:
        state = session_state(request)
        return _limits(state.data, _now()) if state.data is not None else None


def record_activity(request: Request) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    with _session_lock:
        state = session_state(request)
        if state.data is None:
            return None, state.ended
        now = _now()
        state.data["active_at"] = now
        return _limits(state.data, now), None


def is_secure_request(request: Optional[Request]) -> bool:
    if request is None:
        return settings.debug is False
    forwarded = request.headers.get("x-forwarded-proto", "")
    if forwarded:
        return forwarded.split(",")[0].strip().lower() == "https"
    return request.url.scheme == "https"


def _cookie_max_age(session_id: str) -> int:
    with _session_lock:
        record = _session_store.get(_unsign(session_id) or "")
        if record is None:
            return _longest_hours() * 3600
        return max(1, math.ceil(record["login_at"] + int(record["issued_hours"]) * 3600 - _now()))


def set_session_cookie(
    response: Response, session_id: str, request: Optional[Request] = None
) -> None:
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_id,
        max_age=_cookie_max_age(session_id),
        httponly=True,
        secure=is_secure_request(request),
        samesite="lax",
        path="/",
    )


def clear_session_cookie(response: Response, request: Optional[Request] = None) -> None:
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
        httponly=True,
        secure=is_secure_request(request),
        samesite="lax",
    )


def cleanup_expired_sessions() -> int:
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
