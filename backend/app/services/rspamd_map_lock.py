"""One writer at a time for the Rspamd maps.

A map is written whole: the app reads it, changes its part and saves it all
back through mailcow. Two writers at once (the scheduled suppression sync, a
page action, clearing the app's blocks, the map editor) would each save what
they read, and the later one would undo the other. Every writer holds this
lock from its read to its save.

The sync runs on worker threads, each with its own event loop, so the lock is
a thread lock. Code on the request event loop takes it through a thread, so
waiting for it never blocks the loop.
"""
import asyncio
import threading
from contextlib import asynccontextmanager, contextmanager

_LOCK = threading.Lock()
# Long enough for a sync on a slow mailcow, short enough that a stuck writer
# does not hang a request for good
WAIT_SECONDS = 120


class MapBusyError(Exception):
    """Another write to the Rspamd maps did not finish in time."""

    def __init__(self):
        super().__init__("Another change to the Rspamd maps is still running. Try again in a minute.")


@contextmanager
def map_write_lock():
    """For worker threads."""
    if not _LOCK.acquire(timeout=WAIT_SECONDS):
        raise MapBusyError()
    try:
        yield
    finally:
        _LOCK.release()


def _release_if_taken(waiting) -> None:
    if not waiting.cancelled() and waiting.exception() is None and waiting.result():
        _LOCK.release()


@asynccontextmanager
async def map_write_lock_async():
    """For code on the request event loop."""
    waiting = asyncio.get_running_loop().run_in_executor(None, _LOCK.acquire, True, WAIT_SECONDS)
    try:
        acquired = await asyncio.shield(waiting)
    except asyncio.CancelledError:
        # The request went away while the thread still waits: whenever that
        # thread does get the lock, give it straight back
        waiting.add_done_callback(_release_if_taken)
        raise
    if not acquired:
        raise MapBusyError()
    try:
        yield
    finally:
        _LOCK.release()
