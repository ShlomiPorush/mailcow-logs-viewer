"""Lifecycle-owned reclamation of expired in-memory authentication records."""
import asyncio
import logging
from contextlib import asynccontextmanager, suppress

from ..auth import cleanup_expired_auth_failures
from ..session import cleanup_expired_sessions
from ..routers.auth import _cleanup_oauth_states

logger = logging.getLogger(__name__)
CLEANUP_INTERVAL_SECONDS = 60


async def _cleanup_loop():
    while True:
        for cleanup in (cleanup_expired_sessions, cleanup_expired_auth_failures,
                        _cleanup_oauth_states):
            try:
                cleanup()
            except Exception:
                logger.exception("Authentication store cleanup failed")
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
