import logging
import os
import secrets

# Set before app.config loads, or the demo's read-write actions and Rspamd maps stay off.
for _name in ("MAILCOW_API_KEY", "MAILCOW_API_KEY_RW", "RSPAMD_PASSWORD"):
    os.environ.setdefault(_name, secrets.token_hex(32))

import app.main as app_main
from app.main import app  # noqa: F401

from . import fake_internet, fake_mailcow, network_guard, seed
from .banner import DemoBannerMiddleware
from .rate_limit import WriteRateLimitMiddleware

logger = logging.getLogger(__name__)

network_guard.install()
fake_mailcow.install()
fake_internet.install()

_init_db = app_main.init_db
_traffic = None
_start_scheduler = app_main.start_scheduler


def _demo_init_db():
    from app.database import engine

    seed.prepare_database(engine)
    global _traffic
    _traffic = seed.fill_history(fake_mailcow.server)
    _init_db()


def _demo_start_scheduler():
    seed.run_ingest_blocking()
    _start_scheduler()
    seed.start_live_traffic(fake_mailcow.server, _traffic)
    seed.schedule_nightly_reset()


app.add_middleware(DemoBannerMiddleware)
app.add_middleware(WriteRateLimitMiddleware)

app_main.init_db = _demo_init_db
app_main.start_scheduler = _demo_start_scheduler
logger.warning("[DEMO] Demo mode active: fictional data, no mail server")
