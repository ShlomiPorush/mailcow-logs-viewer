"""What a signed-in person may do, by area of the app (issue #544).

People get the areas agents get (agent_access/scopes.py) through an access
level: Admin (everything, including Settings, users and agents), Operator
(View and Act on every area with actions except Rspamd, which is View only),
Viewer (View on every area) or Custom (the areas ticked). Presets are
resolved when a request is checked, so a new area is covered at once.

Who the person is comes from the request's sign-in on every request, with
one database lookup and no cache, so a change to a user, an OAuth2 entry or
the OAuth2 default applies to the next request. The built-in admin (sign-in
off, the AUTH_USERNAME session or Basic header) needs no lookup.

Every route a person can reach has a rule here: the agent policy's area for
it, or an entry in HUMAN where people differ from agents. A test fails on a
route without one, so a new route cannot open up, or close, by accident.
"""
import logging
import unicodedata
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Tuple

from fastapi import HTTPException
from sqlalchemy import text
from starlette.concurrency import run_in_threadpool
from starlette.requests import HTTPConnection

from . import session as sessions
from .agent_access import scopes as policy
from .agent_access.context import agent_call
from .config import settings

logger = logging.getLogger(__name__)
action_logger = logging.getLogger("mlv.actions")

ADMIN = "admin"
OPERATOR = "operator"
VIEWER = "viewer"
CUSTOM = "custom"
NONE = "none"
ACCESS_LEVELS = (ADMIN, OPERATOR, VIEWER, CUSTOM)
OAUTH2_DEFAULTS = (ADMIN, OPERATOR, VIEWER, NONE)
ACCESS_LABELS = {ADMIN: "Admin", OPERATOR: "Operator", VIEWER: "Viewer", CUSTOM: "Custom"}
SETTINGS_AREA = "settings"
# Operators view the Rspamd maps but do not edit them: a map change filters every message
VIEW_ONLY_FOR_OPERATORS = frozenset({"rspamd"})

DEFAULT_ACCESS_KEY = "users.oauth2_default_access"
DEFAULT_VERSION_KEY = "users.oauth2_default_version"

NOT_PERMITTED = "You do not have permission for this."
NOT_AVAILABLE = "Your access could not be checked right now. Try again in a moment."
READ_ONLY_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


# ── Access levels ──────────────────────────────────────────────────────────

def people_areas() -> Tuple[policy.Area, ...]:
    """The areas a person can be given; Settings is for admins only."""
    return tuple(a for a in policy.AREAS if a.id != SETTINGS_AREA)


def preset_scopes(access: str) -> FrozenSet[str]:
    if access == ADMIN:
        return frozenset(policy.all_scopes())
    out = set()
    if access in (OPERATOR, VIEWER):
        for area in people_areas():
            out.add(policy.read_scope(area.id))
            if access == OPERATOR and area.act and area.id not in VIEW_ONLY_FOR_OPERATORS:
                out.add(policy.write_scope(area.id))
    return frozenset(out)


def custom_scopes(stored: Optional[str]) -> FrozenSet[str]:
    """The stored scopes of a custom user that people can have; Act includes View."""
    allowed = {a.id: a for a in people_areas()}
    known = set(policy.all_scopes())
    out = set()
    for scope in (stored or "").split():
        area, _, kind = scope.partition(":")
        if area in allowed and scope in known:
            out.add(scope)
            if kind == policy.WRITE:
                out.add(policy.read_scope(area))
    return frozenset(out)


def scopes_for(access: str, stored: Optional[str]) -> FrozenSet[str]:
    return custom_scopes(stored) if access == CUSTOM else preset_scopes(access)


def custom_choice(views: Iterable[str], acts: Iterable[str]) -> str:
    """The scope string for the areas ticked for a custom user (never Settings)."""
    ids = {a.id for a in people_areas()}
    return policy.grant_scopes([v for v in views if v in ids], [a for a in acts if a in ids])


def area_choices(scopes: FrozenSet[str]) -> Dict[str, str]:
    """area id -> 'view' or 'act' for the people areas these scopes cover."""
    return {k: v for k, v in policy.areas_of(scopes).items() if k != SETTINGS_AREA}


def normalize_email(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return unicodedata.normalize("NFKC", value.strip()).casefold().strip()


def normalize_username(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return unicodedata.normalize("NFKC", value).casefold()


# ── Who is asking ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Principal:
    kind: str                      # builtin | local | oauth2
    is_admin: bool
    scopes: FrozenSet[str]
    name: Optional[str] = None
    user_id: Optional[int] = None
    auth_version: Optional[int] = None
    email: Optional[str] = None
    email_unverified: bool = False

    def may(self, area: str, kind: str) -> bool:
        if self.is_admin:
            return True
        if area == policy.ANY:
            return kind == policy.READ
        if area == SETTINGS_AREA:
            return False
        return f"{area}:{kind}" in self.scopes

    def ref(self) -> Optional[Dict[str, Any]]:
        """What identifies this person for access that outlives the request (Live Logs); None for the built-in admin."""
        if self.kind == "local":
            return {"kind": "local", "user_id": self.user_id, "auth_version": self.auth_version}
        if self.kind == "oauth2":
            return {"kind": "oauth2", "email": self.email, "unverified": self.email_unverified}
        return None

    @property
    def label(self) -> str:
        if self.kind == "builtin" and not settings.is_authentication_enabled:
            return "anyone (sign-in is off)"
        return _printable(self.name or self.email or "built-in admin")


def _printable(value: str) -> str:
    return "".join(c if c.isprintable() else "?" for c in str(value))[:320]


def builtin_admin(name: Optional[str] = None) -> Principal:
    return Principal("builtin", True, frozenset(policy.all_scopes()), name)


class AccessEnded(Exception):
    """The sign-in no longer gives access (user gone, disabled or changed, or no OAuth2 access): the session ends."""


class SessionEnded(Exception):
    """Raised by the policy check; main.py answers it like a session a limit ended."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class NotPermitted(Exception):
    """Raised by the policy check; main.py answers 403 (an HTML page outside /api)."""


def oauth2_ref(user_info: Dict[str, Any]) -> Dict[str, Any]:
    """What an OAuth2 session is matched by: the provider's email, and whether it said the email is not verified."""
    return {"kind": "oauth2", "email": normalize_email((user_info or {}).get("email")),
            "unverified": (user_info or {}).get("email_verified") is False}


def session_ref(record: Dict[str, Any]) -> Dict[str, Any]:
    """Who a session belongs to. A session stores it from its sign-in (routers/auth.py)."""
    ref = record.get("principal")
    if isinstance(ref, dict):
        return ref
    user_info = record.get("user_info") or {}
    if user_info.get("auth_method") == "basic":
        return {"kind": "builtin"}
    return oauth2_ref(user_info)


def _stored_default(value: Optional[str]) -> str:
    # Nothing stored is today's behaviour (everyone the provider lets in is an
    # admin); a value this version does not know refuses
    if value is None:
        return ADMIN
    return value if value in OAUTH2_DEFAULTS else NONE


def oauth2_access(db, email: str, unverified: bool) -> Tuple[str, Optional[str]]:
    """(access, stored scopes) for an OAuth2 sign-in: its entry, else the default. Raises AccessEnded."""
    row = db.execute(text(
        "SELECT s.value AS default_access, u.id, u.access, u.scopes, u.disabled "
        "FROM (SELECT 1) AS one "
        "LEFT JOIN system_settings s ON s.key = :key "
        "LEFT JOIN users u ON u.kind = 'oauth2' AND u.email_norm = :email AND :email <> '' AND NOT :unverified"),
        {"key": DEFAULT_ACCESS_KEY, "email": email or "", "unverified": bool(unverified)}).first()
    if row.id is not None:
        if row.disabled:
            raise AccessEnded()
        return row.access, row.scopes
    default = _stored_default(row.default_access)
    if default == NONE:
        raise AccessEnded()
    return default, None


def resolve(db, ref: Optional[Dict[str, Any]], name: Optional[str] = None) -> Principal:
    """The person a sign-in reference stands for, as the database says now. Raises AccessEnded."""
    kind = (ref or {}).get("kind", "builtin")
    if kind == "builtin":
        return builtin_admin(name)
    if kind == "local":
        row = db.execute(text(
            "SELECT id, username, username_norm, access, scopes, disabled, auth_version FROM users "
            "WHERE id = :id AND kind = 'local'"), {"id": ref.get("user_id")}).first()
        if (row is None or row.disabled or row.auth_version != ref.get("auth_version")
                or row.username_norm == normalize_username(settings.auth_username)):
            raise AccessEnded()
        return Principal("local", row.access == ADMIN, scopes_for(row.access, row.scopes), row.username,
                         row.id, row.auth_version)
    if kind == "oauth2":
        email = ref.get("email") or ""
        access, stored = oauth2_access(db, email, bool(ref.get("unverified")))
        return Principal("oauth2", access == ADMIN, scopes_for(access, stored), name or email or None,
                         email=email, email_unverified=bool(ref.get("unverified")))
    raise AccessEnded()


def _resolve_now(ref, name) -> Principal:
    from .database import SessionLocal
    db = SessionLocal()
    try:
        return resolve(db, ref, name)
    finally:
        db.close()


def still_resolves(ref: Optional[Dict[str, Any]]) -> Principal:
    """The person a reference stands for now. Raises AccessEnded, and lets a database error through."""
    return _resolve_now(ref, None)


def still_permits(ref: Optional[Dict[str, Any]], area: str, kind: str) -> bool:
    """Whether the person behind a reference may still do this; False on any doubt, a database error included."""
    if ref is None:
        return True
    try:
        return _resolve_now(ref, None).may(area, kind)
    except AccessEnded:
        return False
    except Exception as e:
        logger.warning(f"Could not check a person's access: {e}")
        return False


def _display_name(record: Dict[str, Any]) -> Optional[str]:
    user = record.get("user_info") or {}
    for key in ("email", "username", "preferred_username", "name"):
        if isinstance(user.get(key), str) and user[key]:
            return user[key][:320]
    return None


async def request_principal(connection: HTTPConnection) -> Optional[Principal]:
    """The person behind a request the sign-in middleware let in, or None when nobody signed in.

    Raises SessionEnded when the session no longer gives access (it is ended
    here), and HTTPException 503 when the database cannot say.
    """
    if not settings.is_authentication_enabled:
        return builtin_admin()
    admission = getattr(connection.state, "auth_admission", None)
    if admission == ("basic", None):
        return builtin_admin(settings.auth_username)
    if not (isinstance(admission, tuple) and len(admission) == 2 and admission[0] == "session"):
        return None
    key = admission[1]
    state = sessions.session_by_key(key)
    record = state.data
    if record is None:
        raise SessionEnded(state.ended or sessions.SESSION_ACCESS_CHANGED)
    ref = session_ref(record)
    if ref.get("kind") == "builtin":
        return builtin_admin(_display_name(record) or settings.auth_username)
    try:
        return await run_in_threadpool(_resolve_now, ref, _display_name(record))
    except AccessEnded:
        sessions.end_session(key, sessions.SESSION_ACCESS_CHANGED)
        raise SessionEnded(sessions.SESSION_ACCESS_CHANGED)
    except Exception as e:
        logger.error(f"Could not check a person's access: {e}")
        raise HTTPException(status_code=503, detail=NOT_AVAILABLE, headers={"Retry-After": "5"})


def cookie_access(request) -> str:
    """For routes the middleware lets in without a session check (/api/info, /api/auth/activity):
    "none" without a valid session cookie, "ok" while it gives access, "ended" when it no longer
    does (the session is ended here), "unknown" when the database cannot say."""
    state = sessions.session_state(request)
    if state.data is None:
        return "none"
    ref = session_ref(state.data)
    if ref.get("kind") == "builtin":
        return "ok"
    try:
        _resolve_now(ref, None)
        return "ok"
    except AccessEnded:
        sessions.end_session(state.key, sessions.SESSION_ACCESS_CHANGED)
        return "ended"
    except Exception as e:
        logger.error(f"Could not check a person's access: {e}")
        return "unknown"


def caller_may(request, area: str, kind: str) -> bool:
    """Whether the caller, an agent or a person, may do this; for a handler that filters its answer by caller."""
    if request is None:
        return True
    call = agent_call(request.scope)
    if call is not None:
        return policy.allows(call.grant.scopes, policy.Rule(area, kind))
    principal = getattr(request.state, "principal", None)
    if principal is None:
        # Sign-in off: whoever asks is the built-in admin
        return not settings.is_authentication_enabled
    return principal.may(area, kind)


# ── What each route needs ──────────────────────────────────────────────────

PUBLIC = "public"        # checks its own credentials, or needs none
PAGE = "page"            # a page or document: the sign-in middleware is enough, the page's calls are checked
TOKEN = "token"          # a WebSocket that checks its own one-time token
SIGNED_IN = "signed_in"  # anyone signed in
ADMIN_ONLY = "admin"
AREAS = "areas"          # View or Act on every area listed


@dataclass(frozen=True)
class Need:
    kind: str
    areas: Tuple[Tuple[str, str], ...] = ()

    def met_by(self, principal: Principal) -> bool:
        if self.kind in (PUBLIC, PAGE, TOKEN, SIGNED_IN):
            return True
        if self.kind == AREAS:
            return all(principal.may(area, kind) for area, kind in self.areas)
        return principal.is_admin


def _views(*areas: str) -> Tuple[Tuple[str, str], ...]:
    return tuple((area, policy.READ) for area in areas)


_PUBLIC = Need(PUBLIC)
_PAGE = Need(PAGE)
_SIGNED_IN = Need(SIGNED_IN)
_ADMIN = Need(ADMIN_ONLY)
_SUMMARY = _views("status", "mailboxes", "domains", "outbound", "quarantine")

# Where people differ from the agent policy, or the policy says nothing.
# A list, so a test can find an entry given twice.
HUMAN_ENTRIES: List[Tuple[str, Need]] = [
    # Sign-in: the middleware lets these in, and each checks what it needs itself
    ("GET /api/health", _PUBLIC), ("GET /api/info", _PUBLIC), ("GET /api/auth/login", _PUBLIC),
    ("GET /api/auth/callback", _PUBLIC), ("GET /api/auth/provider-info", _PUBLIC),
    ("POST /api/auth/session", _PUBLIC), ("POST /api/auth/activity", _PUBLIC),
    ("GET /api/auth/verify", _SIGNED_IN), ("GET /api/auth/status", _SIGNED_IN),
    # Signing out works whatever the person's access is now
    ("POST /api/auth/logout", _PUBLIC), ("GET /api/auth/logout", _PUBLIC),
    # The page asks before it offers a mailcow action; every action checks its own area
    ("GET /api/rw-status", _SIGNED_IN),
    # The app's own log carries data from every area
    ("GET /api/status/container-logs", _ADMIN),
    # Several areas in one answer: View on each
    ("GET /api/system/summary", Need(AREAS, _SUMMARY)),
    ("POST /api/system/summary/email", Need(AREAS, _SUMMARY + (("status", policy.WRITE),))),
    ("GET /api/entities/ip", Need(AREAS, _views("messages", "security", "mailboxes", "dmarc", "status"))),
    ("GET /api/entities/address", Need(AREAS, _views("messages", "security", "mailboxes", "outbound"))),
    ("GET /api/entities/domain", Need(AREAS, _views("messages", "security", "mailboxes", "dmarc", "outbound",
                                                    "domains"))),
    # Not offered to agents, but part of an area for people
    ("GET /api/raw-logs/ws-token", Need(AREAS, (("logs", policy.READ),))),
    ("POST /api/dmarc/upload", Need(AREAS, (("dmarc", policy.WRITE),))),
    ("POST /api/suppressions/import", Need(AREAS, (("outbound", policy.WRITE),))),
    # Settings changes, credential checks, test messages and job runs
    *((f"{method} {path}", _ADMIN) for method, path in policy.EXCLUDED
      if (method, path) not in {("POST", "/api/dmarc/upload"), ("POST", "/api/suppressions/import"),
                                ("GET", "/api/raw-logs/ws-token")}
      and not path.startswith(("/api/auth/", "/api/entities/"))),
    # Approving an agent is managing agents
    ("GET /oauth/authorize", _ADMIN), ("GET /oauth/consent", _ADMIN), ("GET /oauth/device", _ADMIN),
    # Agent sign-in, discovery and the MCP endpoint check their own credentials
    ("POST /oauth/device", _PUBLIC), ("POST /oauth/token", _PUBLIC), ("POST /oauth/register", _PUBLIC),
    ("POST /oauth/revoke", _PUBLIC), ("GET /.well-known/oauth-protected-resource", _PUBLIC),
    ("GET /.well-known/oauth-protected-resource/mcp", _PUBLIC),
    ("GET /.well-known/oauth-authorization-server", _PUBLIC),
    ("GET /mcp", _PUBLIC), ("POST /mcp", _PUBLIC), ("DELETE /mcp", _PUBLIC),
    ("GET /agents/skill", _PUBLIC), ("GET /agents/skill/{name:path}", _PUBLIC),
    ("GET /agents/mcp", _PUBLIC), ("GET /agents/mcp/", _PUBLIC),
    # Pages and documents
    ("GET /", _PAGE), ("GET /login", _PAGE), ("GET /docs", _PAGE), ("GET /redoc", _PAGE),
    ("GET /openapi.json", _PAGE), ("GET /{full_path:spa_path}", _PAGE),
    ("WEBSOCKET /ws/raw-logs", Need(TOKEN)),
]
HUMAN: Dict[Tuple[str, str], Need] = {}
for _entry, _need in HUMAN_ENTRIES:
    _method, _path = _entry.split(" ", 1)
    HUMAN[(_method, _path)] = _need

# Whole prefixes that are for admins, whatever the method
ADMIN_PREFIXES = (policy.AGENTS_API_PREFIX, policy.USERS_API_PREFIX)


def need_for(method: str, path: str) -> Optional[Need]:
    """What a person needs for a route template, or None when the route has no rule."""
    method = "GET" if method == "HEAD" else method
    need = HUMAN.get((method, path))
    if need is not None:
        return need
    if any(path == p or path.startswith(p + "/") for p in ADMIN_PREFIXES):
        return _ADMIN
    rule = policy.POLICY.get((method, path))
    if rule is None:
        return None
    if rule.area == policy.ANY:
        return _SIGNED_IN
    if rule.area == SETTINGS_AREA:
        return _ADMIN
    return Need(AREAS, ((rule.area, rule.kind),))


def _route_need(app, endpoint, method: str) -> Tuple[Optional[Need], Optional[str]]:
    from .agent_access.dispatch import _route_index
    paths = _route_index(app).get((endpoint, method)) or []
    if not paths and method == "HEAD":
        paths = _route_index(app).get((endpoint, "GET")) or []
    needs = {need_for(method, path) for path in paths}
    if len(needs) != 1 or None in needs:
        return None, paths[0] if paths else None
    return needs.pop(), paths[0]


async def enforce_people_policy(connection: HTTPConnection) -> None:
    """App-wide dependency: let a person's request run only when their access covers the route.

    Agents' calls are left to enforce_agent_policy. WebSocket routes check
    their own tokens (routers/raw_logs.py).
    """
    if connection.scope.get("type") != "http" or agent_call(connection.scope) is not None:
        return
    method = connection.scope["method"]
    need, template = _route_need(connection.app, connection.scope.get("endpoint"), method)
    if need is not None and need.kind in (PUBLIC, PAGE, TOKEN):
        return
    principal = await request_principal(connection)
    if principal is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    connection.state.principal = principal
    if method not in READ_ONLY_METHODS:
        connection.state.people_action = (principal.label, method, template or connection.url.path)
    if need is None:
        logger.error(f"No access rule for {method} {template or connection.url.path}: refused")
        raise NotPermitted()
    if not need.met_by(principal):
        raise NotPermitted()


class ActionLogMiddleware:
    """One line per change a person asked for: who, the route, and the answer's status.

    Pure ASGI (like the other middlewares in main.py), so WebSocket upgrades pass untouched.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        status = {"code": 500}

        async def send_status(message):
            if message["type"] == "http.response.start":
                status["code"] = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_status)
        finally:
            action = (scope.get("state") or {}).get("people_action")
            if action:
                user, method, template = action
                action_logger.info(f"Action by {user}: {method} {template} answered {status['code']}")
