"""
The demo's example users: Settings > Users shows one per access level, while
nobody can sign in as them, since the demo has no sign-in.
"""
import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from fastapi.testclient import TestClient  # noqa: E402

from app import user_access  # noqa: E402
from app.config import settings  # noqa: E402
from app.main import app  # noqa: E402
from app.services import users_store  # noqa: E402
from demo import seed  # noqa: E402


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _wipe():
    from app.database import get_db_context
    from app.models import SystemSetting, User
    with get_db_context() as db:
        db.query(User).delete(synchronize_session=False)
        db.query(SystemSetting).filter(SystemSetting.key.in_(
            (user_access.DEFAULT_ACCESS_KEY, user_access.DEFAULT_VERSION_KEY))).delete(synchronize_session=False)


@pytest.fixture
def demo_users(monkeypatch):
    """Sign-in off, as in the demo image, with the example users seeded."""
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import init_db
    init_db()
    inner = settings._inner
    for key in ("basic_auth_enabled", "auth_enabled", "oauth2_enabled"):
        monkeypatch.setattr(inner, key, False)
    _wipe()
    assert seed.seed_users() == len(seed.DEMO_USERS)
    yield TestClient(app)
    _wipe()


def test_the_examples_show_in_settings(demo_users):
    body = demo_users.get("/api/users").json()
    users = {u["username"] or u["email"]: u for u in body["users"]}
    assert set(users) == {"maria", "helpdesk", "contractor", "it-lead@example.org", "dana@example.com"}
    assert {u["access"] for u in users.values()} == set(user_access.ACCESS_LEVELS)
    assert users["maria"]["kind"] == "local" and users["dana@example.com"]["kind"] == "oauth2"
    assert users["dana@example.com"]["areas"] == {"messages": "view", "outbound": "view", "security": "act"}
    assert [n for n, u in users.items() if u["disabled"]] == ["contractor"]
    assert not any(u["name_conflict"] for u in users.values())
    # Local users read as people who used the app; OAuth2 entries show no sign-in time
    assert all(users[n]["last_login_at"] for n in ("maria", "helpdesk", "contractor"))
    assert users["it-lead@example.org"]["last_login_at"] is None
    # No sign-in is on, so the page says so instead of showing the built-in admin
    assert body["builtin"]["basic_auth_enabled"] is False and body["oauth2"]["enabled"] is False


def test_nobody_knows_a_local_users_password(demo_users):
    from app.database import get_db_context
    from app.models import User
    with get_db_context() as db:
        hashes = [h for (h,) in db.query(User.password_hash).filter(User.kind == "local")]
    # Each gets its own random password at seeding: none is written down anywhere
    assert len(hashes) == 3 and len(set(hashes)) == 3
    assert not any("password" in spec for spec in seed.DEMO_USERS)
    assert users_store.verify_sign_in("maria", "maria") is None
