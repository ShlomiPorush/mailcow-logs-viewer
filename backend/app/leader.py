import fcntl
from typing import IO, Optional

from fastapi import HTTPException

LOCK_PATH = "/app/data/leader.lock"
RETRY_SECONDS = 2
NOT_LEADER_DETAIL = "Background jobs are starting on this server. Try again in a minute."

_lock_file: Optional[IO] = None


def try_lead() -> bool:
    global _lock_file
    if _lock_file is not None:
        return True
    lock_file = open(LOCK_PATH, "a")
    try:
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lock_file.close()
        return False
    _lock_file = lock_file
    return True


def is_leader() -> bool:
    return _lock_file is not None


def require_leader() -> None:
    if not is_leader():
        raise HTTPException(status_code=503, detail=NOT_LEADER_DETAIL)
