"""
Entry point of the demo image (APP_MODULE=demo.main:app).

Wraps the regular application: importing app.main makes no connection, and
the network guard is installed before the lifespan starts any job, so the
first outbound attempt is already blocked.
"""
import logging

from app.config import settings
from app.main import app  # noqa: F401  (served by uvicorn)

from . import network_guard

logger = logging.getLogger(__name__)

network_guard.install(allowed_hosts=[settings.postgres_host])
logger.warning("[DEMO] Demo mode active: fictional data, no mail server")
