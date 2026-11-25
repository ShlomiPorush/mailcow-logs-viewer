import json
import threading
import time

WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
PER_CLIENT_PER_MINUTE = 30
GLOBAL_PER_MINUTE = 300
MAX_TRACKED_CLIENTS = 10000

MESSAGE = "The demo allows a limited number of changes per minute. Wait a moment and try again."


class _Bucket:
    __slots__ = ("tokens", "updated")

    def __init__(self, capacity, now):
        self.tokens = float(capacity)
        self.updated = now


class WriteRateLimiter:
    def __init__(self, per_client=PER_CLIENT_PER_MINUTE, global_limit=GLOBAL_PER_MINUTE,
                 max_clients=MAX_TRACKED_CLIENTS, clock=time.monotonic):
        self.per_client = per_client
        self.global_limit = global_limit
        self.max_clients = max_clients
        self.clock = clock
        self._lock = threading.Lock()
        self._clients = {}
        self._global = _Bucket(global_limit, clock())

    @staticmethod
    def _take(bucket, capacity, now):
        bucket.tokens = min(capacity, bucket.tokens + (now - bucket.updated) * capacity / 60.0)
        bucket.updated = now
        if bucket.tokens >= 1:
            bucket.tokens -= 1
            return True
        return False

    def allow(self, client):
        now = self.clock()
        with self._lock:
            bucket = self._clients.get(client)
            if bucket is None:
                if len(self._clients) >= self.max_clients:
                    for key, _ in sorted(self._clients.items(), key=lambda kv: kv[1].updated)[:self.max_clients // 2]:
                        del self._clients[key]
                bucket = self._clients[client] = _Bucket(self.per_client, now)
            if not self._take(bucket, self.per_client, now):
                return False
            if not self._take(self._global, self.global_limit, now):
                bucket.tokens = min(self.per_client, bucket.tokens + 1)
                return False
            return True


def client_address(scope):
    for name, value in scope.get("headers") or []:
        if name == b"cf-connecting-ip":
            return value.decode("latin-1").strip()[:64] or "unknown"
    client = scope.get("client")
    return client[0] if client else "unknown"


class WriteRateLimitMiddleware:
    def __init__(self, app, limiter=None):
        self.app = app
        self.limiter = limiter or WriteRateLimiter()

    async def __call__(self, scope, receive, send):
        if (scope["type"] == "http" and scope.get("method") in WRITE_METHODS
                and scope.get("path", "").startswith("/api/")
                and not self.limiter.allow(client_address(scope))):
            body = json.dumps({"detail": MESSAGE}).encode()
            await send({"type": "http.response.start", "status": 429, "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"retry-after", b"10"),
            ]})
            await send({"type": "http.response.body", "body": body})
            return
        await self.app(scope, receive, send)
