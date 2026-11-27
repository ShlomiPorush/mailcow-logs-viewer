import pytest

import app.models
from app import session
from app.database import init_db
from app.routers import auth as auth_router


def database_ready() -> None:
    try:
        init_db()
    except Exception:
        pytest.skip('PostgreSQL not available')


def revoke_all_sessions() -> int:
    return session.revoke_all_sessions_keeping(None, None)[0]


def new_oauth_flow(return_to: str) -> tuple[str, str]:
    browser_value = auth_router._new_browser_value(return_to)
    return auth_router._signed_state(browser_value), browser_value
