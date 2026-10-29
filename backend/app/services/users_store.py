"""Users, the OAuth2 default access, and the checks every change to them passes.

Every change to users or the OAuth2 default, and every Settings save that
touches sign-in, runs under one PostgreSQL advisory lock taken in its own
transaction before its checks: two admins changing at once are checked one
after the other, so neither can leave the app without an admin who can sign
in (the last-admin guard).
"""
import logging
import re
import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import func, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import session as sessions
from .. import user_access as access
from ..config import get_env_locked_keys, settings
from ..models import SystemSetting, User
from ..utils import format_datetime_for_api
from . import passwords

logger = logging.getLogger(__name__)

# pg_advisory_xact_lock key shared by every change to who can sign in ("mlvU")
LOCK_KEY = 0x6D6C7655
USERNAME_RE = re.compile(r"[a-z0-9._@-]{1,64}")
EMAIL_MAX = 320
# At most two password hashes at once for sign-ins: each takes 32 MiB and a CPU
SIGN_IN_HASHES = threading.BoundedSemaphore(2)

NO_ADMIN_LEFT = "This change would leave no admin who can sign in."
STALE_USER = "Someone else changed this user. Reload and try again."
STALE_DEFAULT = "Someone else changed the OAuth2 default access. Reload and try again."
NO_VIEW = "Select View for at least one area."
NOT_FOUND = "This user does not exist."
BUSY = "Too many sign-in attempts at once. Try again in a moment."


class UserError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


class SignInBusy(Exception):
    """Two password hashes are already running."""


def lock(db: Session) -> None:
    db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": LOCK_KEY})


def username_problem(norm: str) -> Optional[str]:
    if not USERNAME_RE.fullmatch(norm or ""):
        return "A username has 1 to 64 characters: letters, digits and . _ @ -"
    return None


def email_problem(norm: str) -> Optional[str]:
    if (not norm or len(norm) > EMAIL_MAX or norm.count("@") != 1 or norm.startswith("@") or norm.endswith("@")
            or any(c.isspace() or not c.isprintable() for c in norm)):
        return "Enter one email address."
    return None


def env_admin_name(source=None) -> str:
    return access.normalize_username((source or settings).auth_username or "")


# ── The OAuth2 default ─────────────────────────────────────────────────────

def read_default(db: Session) -> Dict[str, Any]:
    rows = {r.key: r.value for r in db.query(SystemSetting).filter(
        SystemSetting.key.in_((access.DEFAULT_ACCESS_KEY, access.DEFAULT_VERSION_KEY))).all()}
    try:
        version = int(rows.get(access.DEFAULT_VERSION_KEY) or 0)
    except ValueError:
        version = 0
    return {"value": access._stored_default(rows.get(access.DEFAULT_ACCESS_KEY)), "version": version}


def _write_key(db: Session, key: str, value: str) -> None:
    row = db.query(SystemSetting).filter(SystemSetting.key == key).first()
    if row is None:
        db.add(SystemSetting(key=key, value=value, updated_at=datetime.utcnow()))
    else:
        row.value = value
        row.updated_at = datetime.utcnow()


# ── Who can still sign in as an admin ──────────────────────────────────────

@dataclass(frozen=True)
class SignIn:
    basic: bool
    password: bool
    env_name: str
    oauth2: bool

    @property
    def enabled(self) -> bool:
        return self.basic or self.oauth2


def sign_in_now(source=None) -> SignIn:
    source = source or settings
    return SignIn(bool(source.is_basic_auth_enabled), bool(source.auth_password), env_admin_name(source),
                  bool(source.is_oauth2_enabled))


def usable_admins(db: Session, sign_in: SignIn, default: str) -> int:
    """How many admins can sign in by a method that is on (a default of Admin counts as one)."""
    count = 0
    if sign_in.basic:
        count += 1 if sign_in.password else 0
        count += db.query(func.count(User.id)).filter(
            User.kind == "local", User.access == access.ADMIN, User.disabled.is_(False),
            User.username_norm != sign_in.env_name).scalar() or 0
    if sign_in.oauth2:
        count += 1 if default == access.ADMIN else 0
        count += db.query(func.count(User.id)).filter(
            User.kind == "oauth2", User.access == access.ADMIN, User.disabled.is_(False)).scalar() or 0
    return count


def _guard(db: Session, before: int, sign_in: SignIn, default: str) -> None:
    """Refuse a change after which no admin can sign in. A state that had none
    before is not made worse by a change that adds none."""
    db.flush()
    if sign_in.enabled and before > 0 and usable_admins(db, sign_in, default) == 0:
        db.rollback()
        raise UserError(409, NO_ADMIN_LEFT)


# ── Rows as the API shows them ─────────────────────────────────────────────

def _scopes_from(access_level: str, views, acts) -> str:
    if access_level != access.CUSTOM:
        return ""
    scopes = access.custom_choice(views or [], acts or [])
    if not scopes:
        raise UserError(422, NO_VIEW)
    return scopes


def row(user: User, env_name: Optional[str] = None) -> Dict[str, Any]:
    env_name = env_admin_name() if env_name is None else env_name
    return {
        "id": user.id,
        "kind": user.kind,
        "username": user.username if user.kind == "local" else None,
        "email": user.email if user.kind == "oauth2" else None,
        "access": user.access,
        "areas": access.area_choices(access.scopes_for(user.access, user.scopes)),
        "disabled": bool(user.disabled),
        "name_conflict": user.kind == "local" and user.username_norm == env_name,
        "last_login_at": format_datetime_for_api(user.last_login_at),
        "created_at": format_datetime_for_api(user.created_at),
        "row_version": user.row_version,
    }


def overview(db: Session) -> Dict[str, Any]:
    env_name = env_admin_name()
    users = db.query(User).order_by(User.kind, func.coalesce(User.username_norm, User.email_norm), User.id).all()
    default = read_default(db)
    return {
        "areas": [{"id": a.id, "label": a.label, "view": a.view, "act": a.act} for a in access.people_areas()],
        "presets": [{"id": level, "label": access.ACCESS_LABELS[level],
                     "areas": access.area_choices(access.preset_scopes(level))} for level in access.ACCESS_LEVELS],
        "builtin": {"username": settings.auth_username, "basic_auth_enabled": settings.is_basic_auth_enabled},
        "oauth2": {"enabled": settings.is_oauth2_enabled, "default_access": default["value"],
                   "version": default["version"]},
        "users": [row(u, env_name) for u in users],
    }


# ── Changes ────────────────────────────────────────────────────────────────

def _end_local_sessions(user_id: int) -> None:
    sessions.end_sessions_where(
        lambda record: (record.get("principal") or {}).get("kind") == "local"
        and (record.get("principal") or {}).get("user_id") == user_id,
        sessions.SESSION_ACCESS_CHANGED)


def _end_oauth2_sessions(email_norm: str) -> None:
    sessions.end_sessions_where(
        lambda record: access.session_ref(record).get("kind") == "oauth2"
        and access.session_ref(record).get("email") == email_norm,
        sessions.SESSION_ACCESS_CHANGED)


def create_user(db: Session, *, kind: str, username: Optional[str], email: Optional[str],
                password: Optional[str], access_level: str, views, acts, disabled: bool) -> Dict[str, Any]:
    scopes = _scopes_from(access_level, views, acts)
    now = datetime.utcnow()
    if kind == "local":
        if email:
            raise UserError(422, "A local user has a username, not an email address.")
        name = (username or "").strip()
        norm = access.normalize_username(name)
        problem = username_problem(norm) or passwords.length_problem(password or "")
        if problem:
            raise UserError(422, problem)
        user = User(kind="local", username=name, username_norm=norm, password_hash=passwords.hash_password(password),
                    access=access_level, scopes=scopes, disabled=disabled, created_at=now, updated_at=now)
    else:
        if username or password:
            raise UserError(422, "An OAuth2 entry has an email address only; the provider checks the password.")
        norm = access.normalize_email(email)
        problem = email_problem(norm)
        if problem:
            raise UserError(422, problem)
        user = User(kind="oauth2", email=(email or "").strip(), email_norm=norm, access=access_level, scopes=scopes,
                    disabled=disabled, created_at=now, updated_at=now)
    lock(db)
    if kind == "local" and norm == env_admin_name():
        db.rollback()
        raise UserError(409, "This is the built-in admin's username. Choose another one.")
    sign_in = sign_in_now()
    default = read_default(db)["value"]
    before = usable_admins(db, sign_in, default)
    db.add(user)
    try:
        _guard(db, before, sign_in, default)
        db.commit()
    except IntegrityError:
        db.rollback()
        if kind == "local":
            raise UserError(409, "A user with this username already exists.")
        raise UserError(409, "There is already an entry for this email address.")
    db.refresh(user)
    return row(user)


def update_user(db: Session, user_id: int, *, access_level: str, views, acts, disabled: bool,
                password: Optional[str], row_version: int) -> Dict[str, Any]:
    scopes = _scopes_from(access_level, views, acts)
    new_hash = None
    if password is not None:
        problem = passwords.length_problem(password)
        if problem:
            raise UserError(422, problem)
        new_hash = passwords.hash_password(password)
    lock(db)
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        db.rollback()
        raise UserError(404, NOT_FOUND)
    if user.row_version != row_version:
        db.rollback()
        raise UserError(409, STALE_USER)
    if new_hash is not None and user.kind != "local":
        db.rollback()
        raise UserError(422, "An OAuth2 entry has no password here; the provider checks it.")
    sign_in = sign_in_now()
    default = read_default(db)["value"]
    before = usable_admins(db, sign_in, default)
    ends_sessions = (new_hash is not None or user.access != access_level
                     or (user.scopes or "") != scopes or bool(user.disabled) != disabled)
    table = User.__table__
    changed = db.execute(
        table.update()
        .where(table.c.id == user_id, table.c.row_version == row_version)
        .values(access=access_level, scopes=scopes, disabled=disabled,
                password_hash=new_hash if new_hash is not None else table.c.password_hash,
                auth_version=table.c.auth_version + (1 if ends_sessions else 0),
                row_version=table.c.row_version + 1, updated_at=datetime.utcnow()))
    if changed.rowcount != 1:
        db.rollback()
        raise UserError(409, STALE_USER)
    _guard(db, before, sign_in, default)
    db.commit()
    db.refresh(user)
    if ends_sessions and user.kind == "local":
        _end_local_sessions(user.id)
    if user.kind == "oauth2" and user.disabled:
        _end_oauth2_sessions(user.email_norm)
    return row(user)


def delete_user(db: Session, user_id: int) -> None:
    lock(db)
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        db.rollback()
        raise UserError(404, NOT_FOUND)
    kind, email_norm = user.kind, user.email_norm
    sign_in = sign_in_now()
    default = read_default(db)["value"]
    before = usable_admins(db, sign_in, default)
    db.delete(user)
    _guard(db, before, sign_in, default)
    db.commit()
    if kind == "local":
        _end_local_sessions(user_id)
    elif default == access.NONE:
        _end_oauth2_sessions(email_norm)


def set_default(db: Session, value: str, version: int) -> Dict[str, Any]:
    lock(db)
    current = read_default(db)
    if current["version"] != version:
        db.rollback()
        raise UserError(409, STALE_DEFAULT)
    sign_in = sign_in_now()
    before = usable_admins(db, sign_in, current["value"])
    _write_key(db, access.DEFAULT_ACCESS_KEY, value)
    _write_key(db, access.DEFAULT_VERSION_KEY, str(version + 1))
    db.flush()
    if sign_in.enabled and before > 0 and usable_admins(db, sign_in, value) == 0:
        db.rollback()
        raise UserError(409, NO_ADMIN_LEFT)
    db.commit()
    return {"default_access": value, "version": version + 1}


def check_sign_in_settings(db: Session, before, allowed: Dict[str, Any]) -> None:
    """For a Settings save that touches sign-in: refuse a built-in admin name a
    local user has, and a change after which no admin can sign in. Takes the
    lock in the save's own transaction, so it is held until the save commits."""
    lock(db)
    locked = get_env_locked_keys()

    def after(key):
        return allowed[key] if key in allowed and key not in locked else getattr(before, key)

    sign_in_before = sign_in_now(before)
    basic_after = bool(after("basic_auth_enabled")) or bool(before.auth_enabled)
    sign_in_after = SignIn(basic_after, bool(after("auth_password")),
                           access.normalize_username(after("auth_username") or ""), bool(after("oauth2_enabled")))
    if sign_in_after.env_name != sign_in_before.env_name and db.query(User.id).filter(
            User.kind == "local", User.username_norm == sign_in_after.env_name).first() is not None:
        db.rollback()
        raise UserError(400, "A local user has this username. Choose another username for the built-in admin.")
    default = read_default(db)["value"]
    if (sign_in_after.enabled and usable_admins(db, sign_in_after, default) == 0
            and usable_admins(db, sign_in_before, default) > 0):
        db.rollback()
        raise UserError(409, NO_ADMIN_LEFT)


# ── Sign-in of a local user ────────────────────────────────────────────────

def verify_sign_in(username: str, password: str) -> Optional[Dict[str, Any]]:
    """The local user these credentials belong to, or None. Always one password
    hash, whether or not the name exists. Raises SignInBusy."""
    if not SIGN_IN_HASHES.acquire(blocking=False):
        raise SignInBusy()
    try:
        from ..database import SessionLocal
        norm = access.normalize_username(username)
        found = None
        if not username_problem(norm) and norm != env_admin_name():
            db = SessionLocal()
            try:
                found = db.execute(text(
                    "SELECT id, username, password_hash, auth_version, disabled FROM users "
                    "WHERE kind = 'local' AND username_norm = :name"), {"name": norm}).first()
            finally:
                db.close()
        if found is None or found.disabled:
            passwords.burn(password)
            return None
        if not passwords.verify_password(password, found.password_hash):
            return None
        return {"user_id": found.id, "username": found.username, "auth_version": found.auth_version}
    finally:
        SIGN_IN_HASHES.release()


def current_auth_version(user_id: int) -> Optional[int]:
    """The user's auth_version now, read fresh; None when it is gone or disabled."""
    from ..database import SessionLocal
    db = SessionLocal()
    try:
        return db.execute(text("SELECT auth_version FROM users WHERE id = :id AND kind = 'local' AND NOT disabled"),
                          {"id": user_id}).scalar()
    finally:
        db.close()


def record_login(user_id: int) -> None:
    from ..database import SessionLocal
    db = SessionLocal()
    try:
        db.execute(text("UPDATE users SET last_login_at = :now WHERE id = :id"),
                   {"now": datetime.utcnow(), "id": user_id})
        db.commit()
    finally:
        db.close()


def name_conflicts(db: Session) -> List[str]:
    """Local users whose name is the built-in admin's: the built-in admin wins and they cannot sign in."""
    name = env_admin_name()
    return [u.username for u in db.query(User).filter(User.kind == "local", User.username_norm == name).all()]
