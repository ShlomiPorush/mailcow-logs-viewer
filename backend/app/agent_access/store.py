"""Grants, codes, tokens and the activity log, in the database.

Every function takes a SQLAlchemy session and runs synchronously; async callers
use run_in_threadpool. Codes and tokens are stored only as SHA-256 hashes. A
code or refresh token changes state under a row lock (SELECT ... FOR UPDATE),
so two concurrent requests can never both use it.
"""
import base64
import functools
import hashlib
import json
import logging
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Tuple

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from ..config import settings
from ..models import AgentAudit, AgentClient, AgentCode, AgentGrant, AgentToken, SystemSetting
from . import live
from .scopes import parse_scopes

logger = logging.getLogger(__name__)

ACCESS_TOKEN_SECONDS = 3600
CODE_SECONDS = 60
CODES_KEPT_MINUTES = 10
ENDED_GRANTS_KEPT_DAYS = 30
AUDIT_KEPT_DAYS = 90
UNUSED_CLIENTS_KEPT_HOURS = 24
MAX_UNUSED_CLIENTS = 200
CLIENT_EVICTION_MIN_AGE_MINUTES = 15
LAST_USED_RESOLUTION = timedelta(seconds=60)

ACCESS_PREFIX = "mlva_"
REFRESH_PREFIX = "mlvr_"
CLIENT_PREFIX = "mlvc_"


def now() -> datetime:
    return datetime.utcnow()


def token_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def new_secret(prefix: str) -> str:
    return prefix + secrets.token_urlsafe(32)


def pkce_matches(verifier: Optional[str], challenge: str) -> bool:
    """RFC 7636 S256: BASE64URL(SHA256(verifier)) == challenge."""
    if not verifier or not (43 <= len(verifier) <= 128):
        return False
    digest = hashlib.sha256(verifier.encode("ascii", "replace")).digest()
    expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return secrets.compare_digest(expected, challenge)


# ── Sign-in fingerprint ────────────────────────────────────────────────────
# The settings that decide who can sign in, as in routers/settings.py
# (_SESSION_BOUND_SETTING_KEYS; a test keeps the two lists equal). A change to
# any of them, from the Settings page or from ENV and a restart, disconnects
# every agent for good: the last fingerprint is stored, so changing a value
# back does not bring the grants back.
SIGN_IN_KEYS = (
    "basic_auth_enabled", "auth_username", "auth_password",
    "oauth2_enabled", "oauth2_issuer_url", "oauth2_authorization_url", "oauth2_token_url",
    "oauth2_userinfo_url", "oauth2_client_id", "oauth2_client_secret", "session_secret_key",
)
_SECRET_KEYS = frozenset({"auth_password", "oauth2_client_secret", "session_secret_key"})
_FINGERPRINT_KEY = "agent_access_sign_in_fingerprint"
_fingerprint_lock = threading.Lock()
_known_fingerprint: Optional[str] = None
# Called with no arguments when every grant was revoked (drops consents in memory)
on_disconnect_all: List[Callable[[], None]] = []


@functools.lru_cache(maxsize=16)
def _stretched(value: str) -> str:
    """A slow one-way hash of a secret, so the stored fingerprint never holds it."""
    return hashlib.pbkdf2_hmac("sha256", value.encode("utf-8"), b"mlv-agent-access", 100_000).hex()


def sign_in_fingerprint() -> str:
    parts = []
    for key in SIGN_IN_KEYS:
        value = getattr(settings, key, None)
        if key == "basic_auth_enabled":
            value = settings.is_basic_auth_enabled
        text = "" if value is None else str(value)
        parts.append(f"{key}={_stretched(text) if key in _SECRET_KEYS and text else text}")
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


def check_sign_in_unchanged(db: Session) -> bool:
    """Compare sign-in settings with the stored fingerprint; disconnect all agents on a change.

    Returns True when nothing changed. The first call on a fresh database
    stores the fingerprint and disconnects nothing.
    """
    global _known_fingerprint
    current = sign_in_fingerprint()
    if current == _known_fingerprint:
        return True
    with _fingerprint_lock:
        row = db.query(SystemSetting).filter(SystemSetting.key == _FINGERPRINT_KEY).with_for_update().first()
        if row is None:
            db.add(SystemSetting(key=_FINGERPRINT_KEY, value=current, updated_at=now()))
            db.commit()
            _known_fingerprint = current
            return True
        if row.value == current:
            db.commit()
            _known_fingerprint = current
            return True
        count = _revoke_all(db, "sign_in_changed")
        db.query(AgentCode).filter(AgentCode.used_at.is_(None)).delete(synchronize_session=False)
        row.value = current
        row.updated_at = now()
        db.commit()
        _known_fingerprint = current
    for callback in on_disconnect_all:
        try:
            callback()
        except Exception:
            logger.exception("Agent access: a disconnect callback failed")
    if count:
        logger.warning(f"Sign-in settings changed: disconnected {count} agent(s)")
    return False


# ── Activity log ───────────────────────────────────────────────────────────

def audit(db: Session, event: str, grant: Optional["GrantInfo"] = None, *, grant_id: Optional[int] = None,
          agent_name: Optional[str] = None, tool: Optional[str] = None, method: Optional[str] = None,
          path: Optional[str] = None, http_status: Optional[int] = None, outcome: Optional[str] = None,
          detail: Optional[str] = None, commit: bool = True) -> None:
    db.add(AgentAudit(
        grant_id=grant.id if grant else grant_id,
        agent_name=(grant.name if grant else agent_name),
        at=now(), event=event, tool=tool, method=method,
        path=(path or None) and path[:512], http_status=http_status, outcome=outcome,
        detail=(detail or None) and detail[:300],
    ))
    if commit:
        db.commit()


# ── Clients registered with DCR ────────────────────────────────────────────

def register_client(db: Session, name: str, redirect_uris: List[str], ip: str) -> Optional[AgentClient]:
    """Store a DCR client; None when the table is full of clients that cannot be evicted.

    A full table never blocks onboarding for long: the oldest client that has
    no grant, no live code and is older than a few minutes makes room.
    """
    unused = db.query(AgentClient).filter(
        ~AgentClient.client_id.in_(select(AgentGrant.client_id).where(AgentGrant.revoked_at.is_(None)))
    )
    if unused.count() >= MAX_UNUSED_CLIENTS:
        cutoff = now() - timedelta(minutes=CLIENT_EVICTION_MIN_AGE_MINUTES)
        live_codes = select(AgentCode.client_id).where(AgentCode.used_at.is_(None), AgentCode.expires_at > now())
        victim = unused.filter(AgentClient.created_at < cutoff, ~AgentClient.client_id.in_(live_codes)) \
            .order_by(AgentClient.last_used_at.asc().nullsfirst(), AgentClient.created_at.asc()).first()
        if victim is None:
            return None
        db.delete(victim)
    client = AgentClient(client_id=CLIENT_PREFIX + secrets.token_urlsafe(16), client_name=name,
                         redirect_uris=list(redirect_uris), created_at=now(), created_ip=ip[:64])
    db.add(client)
    db.commit()
    db.refresh(client)
    return client


def get_client(db: Session, client_id: str) -> Optional[AgentClient]:
    if not client_id or not client_id.startswith(CLIENT_PREFIX) or len(client_id) > 64:
        return None
    return db.query(AgentClient).filter(AgentClient.client_id == client_id).first()


# ── Grants ─────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class GrantInfo:
    id: int
    name: str
    client_id: str
    scopes: FrozenSet[str]
    expires_at: datetime
    publisher: Optional[str]


def _info(grant: AgentGrant) -> GrantInfo:
    return GrantInfo(grant.id, grant.display_name, grant.client_id, parse_scopes(grant.scopes),
                     grant.expires_at, grant.publisher)


def _grant_active(grant: Optional[AgentGrant]) -> bool:
    return bool(grant and grant.revoked_at is None and grant.expires_at > now())


def _revoke(db: Session, grant: AgentGrant, reason: str) -> bool:
    if grant.revoked_at is not None:
        return False
    grant.revoked_at = now()
    grant.revoke_reason = reason
    db.query(AgentToken).filter(AgentToken.grant_id == grant.id).delete(synchronize_session=False)
    audit(db, "grant_revoked", grant_id=grant.id, agent_name=grant.display_name, outcome="ok",
          detail=reason, commit=False)
    logger.info(f"Agent '{grant.display_name}' disconnected ({reason})")
    return True


def _revoke_all(db: Session, reason: str) -> int:
    grants = db.query(AgentGrant).filter(AgentGrant.revoked_at.is_(None)).all()
    return sum(1 for g in grants if _revoke(db, g, reason))


def revoke_grant(db: Session, grant_id: int, reason: str = "disconnected") -> bool:
    grant = db.query(AgentGrant).filter(AgentGrant.id == grant_id).with_for_update().first()
    if grant is None:
        return False
    changed = _revoke(db, grant, reason)
    db.commit()
    return changed


def revoke_all(db: Session, reason: str = "disconnected") -> int:
    count = _revoke_all(db, reason)
    db.commit()
    return count


def _issue_tokens(db: Session, grant: AgentGrant) -> Dict[str, Any]:
    access, refresh = new_secret(ACCESS_PREFIX), new_secret(REFRESH_PREFIX)
    issued = now()
    access_expires = min(issued + timedelta(seconds=ACCESS_TOKEN_SECONDS), grant.expires_at)
    db.add(AgentToken(grant_id=grant.id, kind="access", token_hash=token_hash(access), client_id=grant.client_id,
                      created_at=issued, expires_at=access_expires))
    db.add(AgentToken(grant_id=grant.id, kind="refresh", token_hash=token_hash(refresh), client_id=grant.client_id,
                      created_at=issued, expires_at=grant.expires_at))
    return {
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": max(1, int((access_expires - issued).total_seconds())),
        "refresh_token": refresh,
        "scope": grant.scopes,
    }


# ── Codes ──────────────────────────────────────────────────────────────────

def create_code(db: Session, *, client_id: str, redirect_uri: str, code_challenge: str, resource: str,
                details: Dict[str, Any]) -> str:
    code = secrets.token_urlsafe(32)
    db.add(AgentCode(code_hash=token_hash(code), client_id=client_id, redirect_uri=redirect_uri,
                     code_challenge=code_challenge, resource=resource, details=details,
                     created_at=now(), expires_at=now() + timedelta(seconds=CODE_SECONDS)))
    db.commit()
    return code


class TokenError(Exception):
    """An OAuth error for the token endpoint (RFC 6749 5.2)."""

    def __init__(self, error: str, description: str):
        super().__init__(description)
        self.error = error
        self.description = description


def exchange_code(db: Session, *, code: str, client_id: str, redirect_uri: str, verifier: str,
                  resource: Optional[str]) -> Dict[str, Any]:
    """Turn a code into the grant and its first tokens, once.

    A code presented again with every binding right (client, redirect address
    and PKCE verifier) means it leaked: the grant it made is disconnected. A
    code presented with a wrong binding is refused and stays usable, so a
    leaked code without its verifier cannot be used to disconnect anyone.
    """
    row = db.query(AgentCode).filter(AgentCode.code_hash == token_hash(code or "")).with_for_update().first()
    if row is None or row.client_id != client_id or row.redirect_uri != redirect_uri \
            or not pkce_matches(verifier, row.code_challenge):
        db.rollback()
        raise TokenError("invalid_grant", "The code is not valid.")
    if row.used_at is not None:
        if row.grant_id:
            grant = db.query(AgentGrant).filter(AgentGrant.id == row.grant_id).with_for_update().first()
            if grant is not None:
                _revoke(db, grant, "code_reused")
        db.commit()
        raise TokenError("invalid_grant", "The code was already used.")
    if row.expires_at <= now():
        db.rollback()
        raise TokenError("invalid_grant", "The code has expired.")
    if resource is not None and not live.same_resource(resource, row.resource):
        db.rollback()
        raise TokenError("invalid_target", "The resource is not this server.")
    d = row.details
    grant = AgentGrant(
        client_id=client_id, client_kind=d["client_kind"], display_name=d["display_name"],
        declared_name=d["declared_name"], publisher=d.get("publisher"), redirect_uri=redirect_uri,
        scopes=d["scopes"], resource=row.resource, approved_by=d.get("approved_by"),
        created_at=now(), expires_at=now() + timedelta(days=int(d["days"])),
    )
    db.add(grant)
    db.flush()
    row.used_at = now()
    row.grant_id = grant.id
    tokens = _issue_tokens(db, grant)
    if d["client_kind"] == "dcr":
        db.query(AgentClient).filter(AgentClient.client_id == client_id).update({"last_used_at": now()})
    audit(db, "grant_created", grant_id=grant.id, agent_name=grant.display_name, outcome="ok",
          detail=f"{grant.scopes} until {grant.expires_at.isoformat(timespec='minutes')}Z", commit=False)
    db.commit()
    logger.info(f"Agent '{grant.display_name}' connected ({grant.scopes})")
    return tokens


def refresh_tokens(db: Session, *, refresh_token: str, client_id: str, scope: Optional[str],
                   resource: Optional[str]) -> Dict[str, Any]:
    """Exchange a refresh token for a new pair; the old one is spent.

    A spent refresh token presented again by its own client means it leaked:
    the grant is disconnected. A scope parameter may only narrow; the grant
    itself never changes.
    """
    row = db.query(AgentToken).filter(AgentToken.token_hash == token_hash(refresh_token or ""),
                                      AgentToken.kind == "refresh").with_for_update().first()
    if row is None or row.client_id != client_id:
        db.rollback()
        raise TokenError("invalid_grant", "The refresh token is not valid.")
    grant = db.query(AgentGrant).filter(AgentGrant.id == row.grant_id).with_for_update().first()
    if row.rotated_at is not None:
        if grant is not None:
            _revoke(db, grant, "refresh_reused")
        db.commit()
        raise TokenError("invalid_grant", "The refresh token was already used.")
    if not _grant_active(grant) or row.expires_at <= now():
        db.rollback()
        raise TokenError("invalid_grant", "This connection has ended. Connect the agent again.")
    if resource is not None and not live.same_resource(resource, grant.resource):
        db.rollback()
        raise TokenError("invalid_target", "The resource is not this server.")
    if scope:
        asked = parse_scopes(scope)
        if not asked or not asked <= parse_scopes(grant.scopes):
            db.rollback()
            raise TokenError("invalid_scope", "A refresh cannot add permissions.")
    row.rotated_at = now()
    # Spent access tokens of this grant end with the refresh
    db.query(AgentToken).filter(AgentToken.grant_id == grant.id, AgentToken.kind == "access") \
        .delete(synchronize_session=False)
    tokens = _issue_tokens(db, grant)
    db.commit()
    return tokens


def revoke_token(db: Session, token: str, client_id: str) -> None:
    """RFC 7009: revoking either token of a grant disconnects the grant."""
    row = db.query(AgentToken).filter(AgentToken.token_hash == token_hash(token or "")).first()
    if row is None or row.client_id != client_id:
        db.rollback()
        return
    grant = db.query(AgentGrant).filter(AgentGrant.id == row.grant_id).with_for_update().first()
    if grant is not None:
        _revoke(db, grant, "revoked_by_agent")
    db.commit()


def validate_access_token(db: Session, token: str) -> Optional[GrantInfo]:
    """The grant behind a bearer token, or None when it is not good for this server now."""
    if not token or not token.startswith(ACCESS_PREFIX) or len(token) > 100:
        return None
    check_sign_in_unchanged(db)
    row = db.query(AgentToken).filter(AgentToken.token_hash == token_hash(token),
                                      AgentToken.kind == "access").first()
    if row is None or row.expires_at <= now():
        return None
    grant = db.query(AgentGrant).filter(AgentGrant.id == row.grant_id).first()
    if not _grant_active(grant) or not live.same_resource(grant.resource, live.resource()):
        return None
    if grant.last_used_at is None or now() - grant.last_used_at > LAST_USED_RESOLUTION:
        grant.last_used_at = now()
        db.commit()
    return _info(grant)


# ── Management ─────────────────────────────────────────────────────────────

def list_grants(db: Session) -> List[AgentGrant]:
    """Connected agents first, then those that ended in the last 30 days."""
    since = now() - timedelta(days=ENDED_GRANTS_KEPT_DAYS)
    rows = db.query(AgentGrant).filter(or_(
        AgentGrant.revoked_at.is_(None) & (AgentGrant.expires_at > since),
        AgentGrant.revoked_at > since,
    )).order_by(AgentGrant.created_at.desc()).all()
    return sorted(rows, key=lambda g: (not _grant_active(g),))


def grant_is_active(grant: AgentGrant) -> bool:
    return _grant_active(grant)


def activity(db: Session, grant_id: int, limit: int = 50) -> List[AgentAudit]:
    return db.query(AgentAudit).filter(AgentAudit.grant_id == grant_id) \
        .order_by(AgentAudit.at.desc(), AgentAudit.id.desc()).limit(limit).all()


def cleanup(db: Session) -> None:
    """Delete what is no longer needed: old codes, ended tokens and grants, old activity, unused clients."""
    t = now()
    db.query(AgentCode).filter(AgentCode.created_at < t - timedelta(minutes=CODES_KEPT_MINUTES)) \
        .delete(synchronize_session=False)
    db.query(AgentToken).filter(AgentToken.expires_at < t - timedelta(days=1)).delete(synchronize_session=False)
    db.query(AgentToken).filter(AgentToken.rotated_at < t - timedelta(days=1)).delete(synchronize_session=False)
    ended = t - timedelta(days=ENDED_GRANTS_KEPT_DAYS)
    db.query(AgentGrant).filter(or_(AgentGrant.revoked_at < ended,
                                    and_(AgentGrant.revoked_at.is_(None), AgentGrant.expires_at < ended))) \
        .delete(synchronize_session=False)
    db.query(AgentAudit).filter(AgentAudit.at < t - timedelta(days=AUDIT_KEPT_DAYS)).delete(synchronize_session=False)
    in_use = select(AgentGrant.client_id)
    db.query(AgentClient).filter(
        AgentClient.created_at < t - timedelta(hours=UNUSED_CLIENTS_KEPT_HOURS),
        ~AgentClient.client_id.in_(in_use),
    ).delete(synchronize_session=False)
    db.commit()


def dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
