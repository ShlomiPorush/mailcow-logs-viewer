"""Sign-in shortcuts that only tests need."""
from app import session
from app.routers import auth as auth_router


def revoke_all_sessions() -> int:
    """End every session; returns the generation this revocation started."""
    return session.revoke_all_sessions_keeping(None, None)[0]


def new_oauth_flow(return_to: str) -> tuple[str, str]:
    """A signed state for the provider and the matching value for the browser cookie."""
    browser_value = auth_router._new_browser_value(return_to)
    return auth_router._signed_state(browser_value), browser_value
