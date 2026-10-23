"""Run one /api call for an agent inside the app, under its grant.

The call goes through the whole app (middleware, router, the route's own
validation) exactly like a request from the browser. Which route runs is
decided by the app's router; enforce_agent_policy, an app-wide dependency,
then checks that route against the policy (scopes.py) before its code runs.
A call whose route never reached the check is treated as refused.

Each call holds a slot until the app has finished with it, including work a
route started after answering (BackgroundTasks): two per agent, four in all.
"""
import asyncio
import json
import logging
import posixpath
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote, urlencode

from fastapi import HTTPException
from starlette.requests import HTTPConnection

from ..config import get_cached_active_domains, settings
from . import scopes as policy
from .context import SCOPE_KEY, AgentCall, agent_call

logger = logging.getLogger(__name__)

MAX_BODY_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_RESULT_CHARS = 100_000
TIMEOUT_SECONDS = 60
SLOTS_PER_GRANT = 2
SLOTS_TOTAL = 4
SLOT_WAIT_SECONDS = 10


# ── The policy check inside the app ────────────────────────────────────────

def _route_index(app) -> Dict[Tuple[Any, str], List[str]]:
    """(endpoint function, method) -> the full path templates it serves (built once per app)."""
    index = getattr(app.state, "agent_route_index", None)
    if index is None:
        # FastAPI 0.141 resolves included routers lazily; this is the same walk
        # the route exposure test uses (conftest.registered_routes)
        from fastapi.routing import _iter_routes_with_context

        index = {}
        for original, context in _iter_routes_with_context(app.routes):
            route = original if context is None else (context.starlette_route or context)
            path, methods = getattr(route, "path", None), getattr(route, "methods", None)
            endpoint = getattr(route, "endpoint", None)
            if not path or not methods or endpoint is None:
                continue
            for method in methods:
                index.setdefault((endpoint, method), []).append(path)
        app.state.agent_route_index = index
    return index


def _own_domains() -> set:
    domains = set(d.lower() for d in (get_cached_active_domains() or []))
    domains.update(d.lower() for d in settings.local_domains_list)
    return domains


def _guard_problem(guard: Optional[str], path_params: Dict[str, Any]) -> Optional[str]:
    if guard == "own_domain":
        domain = str(path_params.get("domain", "")).lower().rstrip(".")
        if domain not in _own_domains():
            return f"{domain} is not one of this mail server's domains."
    return None


def decide(app, call: AgentCall, endpoint, method: str, path_params: Dict[str, Any]) -> Optional[str]:
    """None when the call may run, else why not (in words for the agent)."""
    paths = _route_index(app).get((endpoint, method)) or []
    if not paths:
        return "This address is not part of the app's API."
    rules = set()
    for path in paths:
        reason = policy.excluded_reason(method, path)
        if reason:
            call.path_template = path
            return f"Not available to agents: {reason}."
        rule = policy.POLICY.get((method, path))
        if rule is None:
            return "Not available to agents."
        rules.add(rule)
    if len(rules) != 1:
        return "Not available to agents."
    rule = rules.pop()
    call.path_template = paths[0]
    call.area = rule.area
    if rule.kind != call.mode:
        if rule.kind == policy.WRITE:
            return "This call changes something: use perform_action."
        return "This call only reads: use read_api."
    if not policy.allows(call.grant.scopes, rule):
        label = next((a.label for a in policy.AREAS if a.id == rule.area), rule.area)
        what = "Act" if rule.kind == policy.WRITE else "View"
        return (f"This connection does not have {what} for {label} ({rule.area}:{rule.kind}). "
                "The person who connected you can reconnect you with that permission.")
    return _guard_problem(rule.guard, path_params)


async def enforce_agent_policy(connection: HTTPConnection) -> None:
    """App-wide dependency: let an agent's call run only when its grant covers the route.

    Typed HTTPConnection so it also applies to WebSocket routes, where it does nothing.
    """
    call = agent_call(connection.scope)
    if call is None:
        return
    reason = decide(connection.app, call, connection.scope.get("endpoint"), connection.scope["method"],
                    connection.path_params)
    call.checked = True
    if reason:
        call.denied = reason
        raise HTTPException(status_code=403, detail=reason)


# ── Running a call ─────────────────────────────────────────────────────────

@dataclass
class CallResult:
    status: int
    content_type: str
    text: str
    truncated: bool
    outcome: str           # ok | error | denied | accepted
    denied: Optional[str] = None
    path_template: Optional[str] = None


class Busy(Exception):
    pass


class _Slots:
    def __init__(self):
        self.total = 0
        self.per_grant: Dict[int, int] = {}
        self.changed = asyncio.Event()

    def try_take(self, grant_id: int) -> bool:
        if self.total >= SLOTS_TOTAL or self.per_grant.get(grant_id, 0) >= SLOTS_PER_GRANT:
            return False
        self.total += 1
        self.per_grant[grant_id] = self.per_grant.get(grant_id, 0) + 1
        return True

    def give_back(self, grant_id: int) -> None:
        self.total -= 1
        left = self.per_grant.get(grant_id, 1) - 1
        if left:
            self.per_grant[grant_id] = left
        else:
            self.per_grant.pop(grant_id, None)
        self.changed.set()
        self.changed = asyncio.Event()


_slots: Optional[_Slots] = None
_running: set = set()


async def _take_slot(grant_id: int) -> None:
    global _slots
    if _slots is None:
        _slots = _Slots()
    deadline = asyncio.get_running_loop().time() + SLOT_WAIT_SECONDS
    while not _slots.try_take(grant_id):
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise Busy()
        try:
            await asyncio.wait_for(_slots.changed.wait(), remaining)
        except asyncio.TimeoutError:
            raise Busy()


def check_path(path: str) -> Optional[str]:
    """Why an address cannot be called, or None. Only plain /api paths."""
    if not isinstance(path, str) or not path.startswith("/api/") or len(path) > 1000:
        return "The path must start with /api/."
    if any(c in path for c in "?#%\\") or any(ord(c) < 33 or ord(c) == 127 for c in path):
        return "Give the path without a query string, encoding or spaces; put parameters in query."
    if posixpath.normpath(path) != path.rstrip("/") or "//" in path:
        return "The path must not contain '..' or empty segments."
    return None


def _query_string(query: Optional[Dict[str, Any]]) -> bytes:
    if not query:
        return b""
    pairs = []
    for key, value in query.items():
        values = value if isinstance(value, list) else [value]
        for v in values:
            if isinstance(v, bool):
                v = "true" if v else "false"
            elif v is None:
                continue
            pairs.append((str(key), str(v)))
    return urlencode(pairs).encode("ascii")


def _summarize(content_type: str, raw: bytes) -> Tuple[str, Optional[Any]]:
    text = raw.decode("utf-8", errors="replace")
    if "json" in content_type:
        try:
            data = json.loads(text)
            return json.dumps(data, ensure_ascii=False, separators=(",", ":")), data
        except ValueError:
            pass
    return text, None


def _reports_error(data: Any) -> bool:
    """A 2xx answer that says it failed: {"status": "error"} or {"success": false}."""
    return isinstance(data, dict) and (data.get("status") == "error" or data.get("success") is False)


async def call_api(app, grant, mode: str, method: str, path: str, query: Optional[Dict[str, Any]],
                   body: Any, client: Optional[Tuple[str, int]]) -> CallResult:
    method = method.upper()
    body_bytes = b""
    headers: List[Tuple[bytes, bytes]] = [(b"accept", b"application/json, text/csv;q=0.9, */*;q=0.1"),
                                          (b"user-agent", b"mlv-agent")]
    if body is not None:
        body_bytes = json.dumps(body).encode("utf-8")
        if len(body_bytes) > MAX_BODY_BYTES:
            return CallResult(413, "text/plain", "The body is too large (256 KB at most).", False, "error")
        headers.append((b"content-type", b"application/json"))
    headers.append((b"content-length", str(len(body_bytes)).encode("ascii")))
    call = AgentCall(grant=grant, mode=mode)
    scope = {
        "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"}, "http_version": "1.1",
        "method": method, "scheme": "http", "path": path, "raw_path": quote(path).encode("ascii"),
        "root_path": "", "query_string": _query_string(query), "headers": headers,
        "client": client or ("127.0.0.1", 0), "server": ("mlv-agent", 80),
        SCOPE_KEY: call,
    }

    await _take_slot(grant.id)
    disconnect = asyncio.Event()
    finished = asyncio.Event()
    sent_body = False
    response: Dict[str, Any] = {"status": 500, "headers": [], "body": bytearray(), "truncated": False}

    async def receive():
        nonlocal sent_body
        if not sent_body:
            sent_body = True
            return {"type": "http.request", "body": body_bytes, "more_body": False}
        await disconnect.wait()
        return {"type": "http.disconnect"}

    async def send(message):
        if message["type"] == "http.response.start":
            response["status"] = message["status"]
            response["headers"] = message.get("headers", [])
        elif message["type"] == "http.response.body":
            if not response["truncated"]:
                chunk = message.get("body", b"")
                room = MAX_RESPONSE_BYTES - len(response["body"])
                response["body"].extend(chunk[:room])
                if len(chunk) > room:
                    # Enough: tell a streaming answer the reader has gone
                    response["truncated"] = True
                    disconnect.set()
                    finished.set()
            if not message.get("more_body", False):
                finished.set()

    task = asyncio.create_task(app(scope, receive, send))
    _running.add(task)

    def done(t: asyncio.Task):
        _running.discard(t)
        _slots.give_back(grant.id)
        finished.set()
        if not t.cancelled() and t.exception() is not None and not response["truncated"]:
            logger.warning(f"Agent call {method} {path} ended with {type(t.exception()).__name__}: {t.exception()}")

    task.add_done_callback(done)
    try:
        await asyncio.wait_for(finished.wait(), TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        disconnect.set()
        return CallResult(504, "text/plain",
                          "No answer within 60 seconds. If this was an action it may still be running; "
                          "check its result with a read before trying again.", False, "accepted",
                          path_template=call.path_template)

    headers_map = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in response["headers"]}
    content_type = headers_map.get("content-type", "")
    status = response["status"]
    if not call.checked:
        if status in (404, 405):
            return CallResult(status, "text/plain", "No such address in the app's API (or not for this method).",
                              False, "error")
        # The route ran without the policy check: never hand its answer to the agent
        logger.error(f"Agent call {method} {path} reached a route without the agent policy check")
        return CallResult(403, "text/plain", "Not available to agents.", False, "denied")
    if call.denied:
        return CallResult(403, "text/plain", call.denied, False, "denied", denied=call.denied,
                          path_template=call.path_template)
    text, data = _summarize(content_type, bytes(response["body"]))
    truncated = response["truncated"]
    if len(text) > MAX_RESULT_CHARS:
        text, truncated = text[:MAX_RESULT_CHARS], True
    if status >= 400 or _reports_error(data):
        outcome = "error"
    elif status == 202:
        outcome = "accepted"
    else:
        outcome = "ok"
    return CallResult(status, content_type, text, truncated, outcome, path_template=call.path_template)
