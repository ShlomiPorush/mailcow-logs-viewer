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
VIEW_ONLY_FOR_OPERATORS = frozenset({"rspamd"})

DEFAULT_ACCESS_KEY = "users.oauth2_default_access"
DEFAULT_VERSION_KEY = "users.oauth2_default_version"

NOT_PERMITTED = "You do not have permission for this."
NOT_AVAILABLE = "Your access could not be checked right now. Try again in a moment."
READ_ONLY_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def people_areas() -> Tuple[policy.Area, ...]:
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
    ids = {a.id for a in people_areas()}
    return policy.grant_scopes([v for v in views if v in ids], [a for a in acts if a in ids])


def area_choices(scopes: FrozenSet[str]) -> Dict[str, str]:
    return {k: v for k, v in policy.areas_of(scopes).items() if k != SETTINGS_AREA}


def normalize_email(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return unicodedata.normalize("NFKC", value.strip()).casefold().strip()


def normalize_username(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return unicodedata.normalize("NFKC", value).casefold()


@dataclass(frozen=True)
class Principal:
    kind: str
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
        return any(f"{a}:{kind}" in self.scopes for a in policy.rule_areas(area))

    def ref(self) -> Optional[Dict[str, Any]]:
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
    pass


class SessionEnded(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class NotPermitted(Exception):
    pass


def oauth2_ref(user_info: Dict[str, Any]) -> Dict[str, Any]:
    return {"kind": "oauth2", "email": normalize_email((user_info or {}).get("email")),
            "unverified": (user_info or {}).get("email_verified") is False}


def session_ref(record: Dict[str, Any]) -> Dict[str, Any]:
    return record["principal"]


def _stored_default(value: Optional[str]) -> str:
    if value is None:
        return ADMIN
    return value if value in OAUTH2_DEFAULTS else NONE


def oauth2_access(db, email: str, unverified: bool) -> Tuple[str, Optional[str]]:
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
    return _resolve_now(ref, None)


def still_permits(ref: Optional[Dict[str, Any]], area: str, kind: str) -> bool:
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
    if request is None:
        return True
    call = agent_call(request.scope)
    if call is not None:
        return policy.allows(call.grant.scopes, policy.Rule(area, kind))
    principal = getattr(request.state, "principal", None)
    if principal is None:
        return not settings.is_authentication_enabled
    return principal.may(area, kind)


def caller_is_admin(request) -> bool:
    if request is None:
        return True
    if agent_call(request.scope) is not None:
        return False
    principal = getattr(request.state, "principal", None)
    if principal is None:
        return not settings.is_authentication_enabled
    return principal.is_admin


FAILED_RUN = "The last run failed."


def job_error(request, error):
    if not error or caller_may(request, SETTINGS_AREA, policy.READ):
        return error
    return FAILED_RUN


PUBLIC = "public"
PAGE = "page"
TOKEN = "token"
SIGNED_IN = "signed_in"
ADMIN_ONLY = "admin"
AREAS = "areas"
ANY_AREA = "any_area"


@dataclass(frozen=True)
class Need:
    kind: str
    areas: Tuple[Tuple[str, str], ...] = ()

    def met_by(self, principal: Principal) -> bool:
        if self.kind in (PUBLIC, PAGE, TOKEN, SIGNED_IN):
            return True
        if self.kind == AREAS:
            return all(principal.may(area, kind) for area, kind in self.areas)
        if self.kind == ANY_AREA:
            return any(principal.may(area, kind) for area, kind in self.areas)
        return principal.is_admin


def _views(*areas: str) -> Tuple[Tuple[str, str], ...]:
    return tuple((area, policy.READ) for area in areas)


_PUBLIC = Need(PUBLIC)
_PAGE = Need(PAGE)
_SIGNED_IN = Need(SIGNED_IN)
_ADMIN = Need(ADMIN_ONLY)
_SUMMARY = _views("status", "mailboxes", "domains", "outbound", "quarantine")

HUMAN_ENTRIES: List[Tuple[str, Need]] = [
    ("GET /api/health", _PUBLIC), ("GET /api/info", _PUBLIC), ("GET /api/auth/login", _PUBLIC),
    ("GET /api/auth/callback", _PUBLIC), ("GET /api/auth/provider-info", _PUBLIC),
    ("POST /api/auth/session", _PUBLIC), ("POST /api/auth/activity", _PUBLIC),
    ("GET /api/auth/verify", _SIGNED_IN), ("GET /api/auth/status", _SIGNED_IN),
    ("POST /api/auth/logout", _PUBLIC), ("GET /api/auth/logout", _PUBLIC),
    ("GET /api/rw-status", _SIGNED_IN),
    ("GET /api/status/container-logs", _ADMIN),
    ("GET /api/system/summary", Need(AREAS, _SUMMARY)),
    ("POST /api/system/summary/email", Need(AREAS, _SUMMARY + (("status", policy.WRITE),))),
    ("GET /api/entities/ip", Need(AREAS, _views("messages", "security", "mailboxes", "dmarc", "status"))),
    ("GET /api/entities/address", Need(AREAS, _views("messages", "security", "mailboxes", "outbound"))),
    ("GET /api/entities/domain", Need(AREAS, _views("messages", "security", "mailboxes", "dmarc", "outbound",
                                                    "domains"))),
    ("GET /api/raw-logs/ws-token", Need(AREAS, (("logs", policy.READ),))),
    ("POST /api/dmarc/upload", Need(AREAS, (("dmarc", policy.WRITE),))),
    ("POST /api/suppressions/import", Need(AREAS, (("outbound", policy.WRITE),))),
    *((f"{method} {path}", _ADMIN) for method, path in policy.EXCLUDED
      if (method, path) not in {("POST", "/api/dmarc/upload"), ("POST", "/api/suppressions/import"),
                                ("GET", "/api/raw-logs/ws-token")}
      and not path.startswith(("/api/auth/", "/api/entities/"))),
    ("POST /api/users/password-check", _ADMIN),
    ("GET /oauth/authorize", _ADMIN), ("GET /oauth/consent", _ADMIN), ("GET /oauth/device", _ADMIN),
    ("POST /oauth/device", _PUBLIC), ("POST /oauth/token", _PUBLIC), ("POST /oauth/register", _PUBLIC),
    ("POST /oauth/revoke", _PUBLIC), ("GET /.well-known/oauth-protected-resource", _PUBLIC),
    ("GET /.well-known/oauth-protected-resource/mcp", _PUBLIC),
    ("GET /.well-known/oauth-authorization-server", _PUBLIC),
    ("GET /mcp", _PUBLIC), ("POST /mcp", _PUBLIC), ("DELETE /mcp", _PUBLIC),
    ("GET /agents/skill", _PUBLIC), ("GET /agents/skill/{name:path}", _PUBLIC),
    ("GET /agents/mcp", _PUBLIC), ("GET /agents/mcp/", _PUBLIC),
    ("GET /", _PAGE), ("GET /login", _PAGE), ("GET /docs", _PAGE), ("GET /redoc", _PAGE),
    ("GET /openapi.json", _PAGE), ("GET /{full_path:spa_path}", _PAGE),
    ("WEBSOCKET /ws/raw-logs", Need(TOKEN)),
]
HUMAN: Dict[Tuple[str, str], Need] = {}
for _entry, _need in HUMAN_ENTRIES:
    _method, _path = _entry.split(" ", 1)
    HUMAN[(_method, _path)] = _need

ADMIN_PREFIXES = (policy.AGENTS_API_PREFIX, policy.USERS_API_PREFIX)


def need_for(method: str, path: str) -> Optional[Need]:
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
    if rule.area in policy.ALTERNATIVES:
        return Need(ANY_AREA, tuple((area, rule.kind) for area in policy.ALTERNATIVES[rule.area]))
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
