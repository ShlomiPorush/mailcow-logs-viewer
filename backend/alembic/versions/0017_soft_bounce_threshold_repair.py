"""Lift automatic soft-bounce suppressions and count their bounces again.

With Count then suppress, earlier versions could suppress a recipient below
the Soft Bounce Threshold: an existing entry became active again on any
soft bounce, and a bounce could be counted twice, so the stored counts
cannot be trusted. Every automatic soft-bounce entry, active or not and at
any count, is turned off and marked so the next Rspamd sync removes it. Its
soft-bounce and bounce counts start again at 0, and its expiry, made longer
by those counts, ends now: new bounces must reach the threshold again, and
the expiry is then worked out from the new bounces only. Manual and imported
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

# Entries not lifted yet; a lifted entry is off with no counts
LIFT = (
    "FROM spam_suppressions WHERE source = 'auto' AND reason = 'soft_bounce' "
    "AND (active OR COALESCE(soft_bounce_count, 0) <> 0 OR COALESCE(bounce_count, 0) <> 0)"
)


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
    was_active = bind.execute(text(f"SELECT COUNT(*) {LIFT} AND active")).scalar()
    lifted = bind.execute(text(
        "UPDATE spam_suppressions SET active = false, synced_to_rspamd = false, "
        "soft_bounce_count = 0, bounce_count = 0, "
        "expires_at = LEAST(expires_at, now() AT TIME ZONE 'utc') "
        f"WHERE id IN (SELECT id {LIFT})"
    )).rowcount
    if lifted:
        logger.warning(
            f"[SUPPRESSION] Upgrade: lifted {lifted} automatic soft-bounce suppression(s) "
            f"({was_active} of them active) and reset their bounce counts; the Soft Bounce Threshold "
            f"of {settings.suppression_soft_bounce_threshold} counts new bounces only, and the next "
            f"Rspamd sync removes them"
        )


def downgrade() -> None:
    # The entries are not turned back on, and their counts are not restored
    pass
