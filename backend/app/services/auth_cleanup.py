"""Lifecycle-owned reclamation of expired in-memory authentication records."""
import asyncio
import logging
import time
from contextlib import asynccontextmanager, suppress

from ..auth import cleanup_expired_auth_failures
from ..session import cleanup_expired_sessions
from ..routers.auth import _cleanup_oauth_states
from ..agent_access import mcp as agent_mcp, oauth as agent_oauth

logger = logging.getLogger(__name__)
CLEANUP_INTERVAL_SECONDS = 60
# Agent access rows (old codes, ended grants, old activity) are tidied less often
AGENT_DB_CLEANUP_SECONDS = 600


def _agent_db_cleanup():
    from ..agent_access import store as agent_store
    from ..database import get_db_context
    with get_db_context() as db:
        agent_store.cleanup(db)


async def _cleanup_loop():
    next_agent_db_cleanup = time.monotonic() + AGENT_DB_CLEANUP_SECONDS
    while True:
        for cleanup in (cleanup_expired_sessions, cleanup_expired_auth_failures,
                        _cleanup_oauth_states, agent_oauth.cleanup, agent_mcp.cleanup):
            try:
                cleanup()
            except Exception:
                logger.exception("Authentication store cleanup failed")
        if time.monotonic() >= next_agent_db_cleanup:
            next_agent_db_cleanup = time.monotonic() + AGENT_DB_CLEANUP_SECONDS
            try:
                await asyncio.to_thread(_agent_db_cleanup)
            except Exception:
                logger.exception("Agent access cleanup failed")
        await asyncio.sleep(CLEANUP_INTERVAL_SECONDS)


@asynccontextmanager
async def auth_store_maintenance():
    task = asyncio.create_task(_cleanup_loop(), name="auth-store-cleanup")
    try:
        yield
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
