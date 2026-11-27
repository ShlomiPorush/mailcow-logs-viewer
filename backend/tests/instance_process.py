import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app import leader, main, raw_logs_worker, scheduler  # noqa: E402
from app.config import settings  # noqa: E402

collected_services = []


def _prepare(lock_path: str) -> None:
    leader.LOCK_PATH = lock_path
    type(settings._inner).raw_logs_collected_list = property(lambda self: list(collected_services))
    scheduler._scheduled_jobs = lambda: ()
    scheduler._startup_runs = lambda: ()

    async def no_fetch():
        return None
    raw_logs_worker.fetch_raw_service_logs = no_fetch


def _status() -> dict:
    return {
        "scheduler": scheduler.scheduler.running,
        "raw_logs": raw_logs_worker.raw_logs_scheduler.running,
        "fetch_interval": settings.fetch_interval,
    }


def _answer(payload) -> None:
    print("@@" + json.dumps(payload), flush=True)


async def _serve() -> None:
    async with main.lifespan(main.app):
        _answer("up")
        while True:
            command = (await asyncio.to_thread(sys.stdin.readline)).strip()
            if command in ("", "exit"):
                break
            if command == "status":
                _answer(_status())
            elif command == "collect":
                collected_services.append("postfix")
                raw_logs_worker.reschedule_raw_logs_jobs()
                _answer(_status())


if __name__ == "__main__":
    _prepare(sys.argv[1])
    asyncio.run(_serve())
