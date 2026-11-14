"""Small in-memory rate limits per client address, and request body limits."""
import threading
import time
from collections import OrderedDict, deque
from typing import Deque

from fastapi import HTTPException, Request

MAX_KEYS = 10000


class Window:
    """At most `limit` events per `seconds` for each key."""

    def __init__(self, limit: int, seconds: int):
        self.limit = limit
        self.seconds = seconds
        self._events: "OrderedDict[str, Deque[float]]" = OrderedDict()
        self._lock = threading.Lock()

    def _recent(self, key: str, now: float) -> Deque[float]:
        events = self._events.get(key)
        if events is None:
            return deque()
        while events and events[0] <= now - self.seconds:
            events.popleft()
        if not events:
            self._events.pop(key, None)
        return events

    def full(self, key: str) -> bool:
        with self._lock:
            return len(self._recent(key, time.monotonic())) >= self.limit

    def hit(self, key: str) -> bool:
        """Count an event; False when the key was already at its limit (not counted)."""
        with self._lock:
            now = time.monotonic()
            events = self._recent(key, now)
            if len(events) >= self.limit:
                return False
            if key not in self._events:
                while len(self._events) >= MAX_KEYS:
                    self._events.popitem(last=False)
                self._events[key] = events
            self._events.move_to_end(key)
            events.append(now)
            return True

    def cleanup(self) -> None:
        with self._lock:
            now = time.monotonic()
            for key in list(self._events):
                self._recent(key, now)


async def read_body(request: Request, limit: int) -> bytes:
    """The request body, refusing it as soon as it passes `limit` bytes (chunked bodies too)."""
    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > limit:
        raise HTTPException(status_code=413, detail="The request is too large.")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > limit:
            raise HTTPException(status_code=413, detail="The request is too large.")
    return bytes(body)
