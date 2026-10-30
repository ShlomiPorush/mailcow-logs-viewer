"""Block details: what happened to each blocked address, kept with it.

Creates suppression_events (the app's start creates it from the model first,
so this only fills the gap) and gives every address already on the list one
before_upgrade event with what the row itself still knows: its reason, last
answer and notes. Nothing more is claimed: the logs behind an older block are
usually gone already, and its recorded time is the upgrade, not the bounce.

Revision ID: 0019
Revises: 0018
Create Date: 2026-10-19
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if "suppression_events" not in sa.inspect(bind).get_table_names():
        op.create_table(
            "suppression_events",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("suppression_id", sa.Integer,
                      sa.ForeignKey("spam_suppressions.id", ondelete="CASCADE"), nullable=False),
            sa.Column("kind", sa.String(30), nullable=False),
            sa.Column("outcome", sa.String(20)),
            sa.Column("recorded_at", sa.DateTime, nullable=False),
            sa.Column("message_time", sa.DateTime),
            sa.Column("reason", sa.Text),
            sa.Column("server_reply", sa.Text),
            sa.Column("dsn", sa.String(20)),
            sa.Column("sender", sa.String(255)),
            sa.Column("recipient", sa.String(255)),
            sa.Column("subject", sa.Text),
            sa.Column("queue_id", sa.String(50)),
            sa.Column("message_id", sa.String(255)),
            sa.Column("correlation_key", sa.String(64)),
            sa.Column("notes", sa.Text),
            sa.Column("expires_at", sa.DateTime),
            sa.Column("log_lines", JSONB),
            sa.Column("logs_shortened", sa.Boolean, server_default=sa.false()),
        )
        op.create_index("idx_suppression_event_owner", "suppression_events", ["suppression_id", "recorded_at"])

    # What every address already on the list still has, marked as such
    bind.execute(sa.text("""
        INSERT INTO suppression_events
            (suppression_id, kind, recorded_at, reason, server_reply, dsn, recipient,
             notes, expires_at, correlation_key, logs_shortened)
        SELECT s.id, 'before_upgrade', now() AT TIME ZONE 'UTC', left(s.reason, 2000), left(s.last_bounce_message, 2000),
               left(s.last_bounce_dsn, 20), left(s.email, 255), left(s.notes, 2000), s.expires_at, s.correlation_key,
               coalesce(length(s.last_bounce_message) > 2000, false)
        FROM spam_suppressions s
        WHERE NOT EXISTS (SELECT 1 FROM suppression_events e WHERE e.suppression_id = s.id)
    """))


def downgrade() -> None:
    op.drop_table("suppression_events")
