"""Authorization requests waiting on the consent page, in memory.

Each belongs to the browser session that opened it and is used once. They
live ten minutes; at most MAX_PENDING wait at a time (the oldest makes room),
and all are dropped when sign-in settings change.
"""
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Dict, FrozenSet, Optional, Tuple

TTL_SECONDS = 600
MAX_PENDING = 50


@dataclass
class PendingRequest:
    id: str
    session_key: str
    client_id: str
    client_kind: str                  # 'dcr' | 'cimd'
    declared_name: str
    publisher: Optional[str]
    redirect_uri: str
    state: Optional[str]
    code_challenge: str
    resource: str
    requested: FrozenSet[str]
    created: float


_pending: Dict[str, PendingRequest] = {}
_lock = threading.RLock()


def _expire(now: float) -> None:
    for key in [k for k, p in _pending.items() if now - p.created > TTL_SECONDS]:
        _pending.pop(key, None)


def add(**fields) -> PendingRequest:
    with _lock:
        now = time.monotonic()
        _expire(now)
        while len(_pending) >= MAX_PENDING:
            _pending.pop(min(_pending, key=lambda k: _pending[k].created), None)
        request = PendingRequest(id=secrets.token_urlsafe(24), created=now, **fields)
        _pending[request.id] = request
        return request


def get(request_id: str, session_key: Optional[str]) -> Optional[PendingRequest]:
    """The request, if it exists and belongs to this session."""
    with _lock:
        _expire(time.monotonic())
        request = _pending.get(request_id or "")
        if request is None or not session_key or not secrets.compare_digest(request.session_key, session_key):
            return None
        return request


def take(request_id: str, session_key: Optional[str]) -> Optional[PendingRequest]:
    """Like get, and removes it: a request is answered once."""
    with _lock:
        request = get(request_id, session_key)
        if request is not None:
            _pending.pop(request.id, None)
        return request


def clear() -> None:
    with _lock:
        _pending.clear()


def cleanup() -> None:
    with _lock:
        _expire(time.monotonic())
