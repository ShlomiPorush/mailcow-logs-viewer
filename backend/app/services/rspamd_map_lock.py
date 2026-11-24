import asyncio
import threading
from contextlib import asynccontextmanager, contextmanager

_LOCK = threading.Lock()
WAIT_SECONDS = 120


class MapBusyError(Exception):

    def __init__(self):
        super().__init__("Another change to the Rspamd maps is still running. Try again in a minute.")


@contextmanager
def map_write_lock():
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
    waiting = asyncio.get_running_loop().run_in_executor(None, _LOCK.acquire, True, WAIT_SECONDS)
    try:
        acquired = await asyncio.shield(waiting)
    except asyncio.CancelledError:
        waiting.add_done_callback(_release_if_taken)
        raise
    if not acquired:
        raise MapBusyError()
    try:
        yield
    finally:
        _LOCK.release()
