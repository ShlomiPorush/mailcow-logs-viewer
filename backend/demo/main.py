"""
Entry point of the demo image (APP_MODULE=demo.main:app).

Wraps the regular application: importing app.main makes no connection, and
the network guard, the fake mailcow server and the fake internet are
installed before the lifespan starts any job, so the first request already
goes to a fake.

Two startup steps are wrapped: before the database is initialised it is
emptied and the fake server receives a week of logs; before the scheduler
starts, the application's own jobs ingest that history. The nightly reset
is scheduled once the scheduler runs.
"""
import logging

import app.main as app_main
from app.config import settings
from app.main import app  # noqa: F401  (served by uvicorn)

from . import fake_internet, fake_mailcow, network_guard, seed

logger = logging.getLogger(__name__)

network_guard.install(allowed_hosts=[settings.postgres_host])
fake_mailcow.install()
fake_internet.install()

_init_db = app_main.init_db
_start_scheduler = app_main.start_scheduler


def _demo_init_db():
    from app.database import engine

    seed.prepare_database(engine)
    seed.fill_history(fake_mailcow.server)
    _init_db()


def _demo_start_scheduler():
    seed.run_ingest_blocking()
    _start_scheduler()
    seed.schedule_nightly_reset()


app_main.init_db = _demo_init_db
app_main.start_scheduler = _demo_start_scheduler
logger.warning("[DEMO] Demo mode active: fictional data, no mail server")
