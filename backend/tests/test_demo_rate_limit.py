"""
The demo's write cap: a per-client and a global budget of writes per
minute, reads and WebSockets untouched, bounded memory.
"""
import asyncio
import json

from demo.rate_limit import WriteRateLimiter, WriteRateLimitMiddleware, client_address


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_each_client_gets_its_own_budget_that_refills():
    clock = Clock()
    limiter = WriteRateLimiter(per_client=3, global_limit=100, clock=clock)
    assert [limiter.allow("a") for _ in range(4)] == [True, True, True, False]
    assert limiter.allow("b") is True
    clock.now += 20  # a third of a minute refills one of three
    assert limiter.allow("a") is True
    assert limiter.allow("a") is False


def test_the_global_budget_caps_all_clients_together():
    limiter = WriteRateLimiter(per_client=5, global_limit=4, clock=Clock())
    results = [limiter.allow(f"client-{i}") for i in range(6)]
    assert results == [True, True, True, True, False, False]


def test_a_refused_global_write_does_not_cost_the_client():
    clock = Clock()
    limiter = WriteRateLimiter(per_client=2, global_limit=1, clock=clock)
    assert limiter.allow("a") is True
    assert limiter.allow("b") is False  # global budget empty
    clock.now += 60
    assert [limiter.allow("b"), limiter.allow("b")] == [True, False]


def test_memory_stays_bounded_when_every_request_claims_a_new_address():
    limiter = WriteRateLimiter(per_client=1, global_limit=10**9, max_clients=100, clock=Clock())
    for i in range(1000):
        limiter.allow(f"198.51.100.{i}")
    assert len(limiter._clients) <= 100


def test_the_cloudflare_header_identifies_the_client():
    scope = {"headers": [(b"cf-connecting-ip", b"203.0.113.7")], "client": ("172.18.0.1", 5000)}
    assert client_address(scope) == "203.0.113.7"
    assert client_address({"headers": [], "client": ("192.0.2.4", 1)}) == "192.0.2.4"


def _call(middleware, method, path, scope_type="http", headers=()):
    sent = []
    scope = {"type": scope_type, "method": method, "path": path, "headers": list(headers), "client": ("192.0.2.9", 1)}

    async def receive():
        return {"type": "http.request"}

    async def send(message):
        sent.append(message)

    asyncio.run(middleware(scope, receive, send))
    return sent


def test_the_middleware_refuses_writes_over_budget_with_a_readable_message():
    reached = []

    async def app(scope, receive, send):
        reached.append(scope["path"])

    middleware = WriteRateLimitMiddleware(app, WriteRateLimiter(per_client=1, global_limit=10, clock=Clock()))
    assert _call(middleware, "POST", "/api/quarantine/release") == []
    refused = _call(middleware, "POST", "/api/quarantine/release")
    assert refused[0]["status"] == 429
    assert "try again" in json.loads(refused[1]["body"])["detail"]
    # Reads, pages and WebSockets are never limited
    _call(middleware, "GET", "/api/quarantine")
    _call(middleware, "POST", "/login")
    _call(middleware, "GET", "/ws/raw-logs", scope_type="websocket")
    assert reached == ["/api/quarantine/release", "/api/quarantine", "/login", "/ws/raw-logs"]
