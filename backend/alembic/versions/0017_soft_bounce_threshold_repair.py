"""Turn off soft-bounce suppressions that started before the threshold.

With Count then suppress, earlier versions could suppress a recipient below
the Soft Bounce Threshold: an existing entry became active again on any
soft bounce, and a bounce could be counted twice. Automatic soft-bounce
entries that are active below the threshold are turned off, and marked so
the next Rspamd sync removes them. Their counts stay; the next soft bounces
turn them on again once the threshold is reached. Manual and imported
entries, hard bounces and stuck-in-queue entries stay as they are, and
nothing changes when soft bounces are suppressed at once or ignored.

Revision ID: 0017
Revises: 0016
Create Date: 2026-10-16
"""
import logging

from alembic import op
from sqlalchemy import text
from sqlalchemy.orm import Session


revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None

logger = logging.getLogger("app.migrations")


def upgrade() -> None:
    from app.config import build_settings

    bind = op.get_bind()
    # The effective settings, with the ones saved from the UI; the app
    # loads those only after the migrations
    session = Session(bind=bind)
    try:
        settings = build_settings(session)
    finally:
        session.close()
    if settings.suppression_soft_bounce_action != "count":
        return
    threshold = settings.suppression_soft_bounce_threshold
    changed = bind.execute(text(
        "UPDATE spam_suppressions SET active = false, synced_to_rspamd = false "
        "WHERE source = 'auto' AND reason = 'soft_bounce' AND active "
        "AND COALESCE(soft_bounce_count, 0) < :threshold"
    ), {"threshold": threshold}).rowcount
    if changed:
        logger.warning(
            f"[SUPPRESSION] Upgrade: turned off {changed} automatic soft-bounce suppression(s) "
            f"below the Soft Bounce Threshold of {threshold}; the next Rspamd sync removes them"
        )


def downgrade() -> None:
    # The entries are not turned back on
    pass
