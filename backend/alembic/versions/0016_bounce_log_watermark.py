"""Remember which Postfix lines bounce detection has counted.

Bounce detection kept the lines it had counted only in memory, so after a
restart it counted the last 10 minutes of bounces again. It now stores the
highest counted postfix_logs id in system_settings. This revision starts
that mark at the newest line already stored: the version before this one
has counted those lines, at least the ones older than its last run.

Revision ID: 0016
Revises: 0015
Create Date: 2026-10-16
"""
from alembic import op


revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None

KEY = "suppression_bounce_log_watermark"


def upgrade() -> None:
    # Keeps a mark that is already there
    op.execute(
        "INSERT INTO system_settings (key, value, updated_at) "
        f"SELECT '{KEY}', COALESCE(MAX(id), 0)::text, now() AT TIME ZONE 'utc' FROM postfix_logs "
        "ON CONFLICT (key) DO NOTHING"
    )


def downgrade() -> None:
    op.execute(f"DELETE FROM system_settings WHERE key = '{KEY}'")
