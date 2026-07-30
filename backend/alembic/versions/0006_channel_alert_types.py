"""Add per-channel alert type subscriptions.

Existing channels keep NULL, which means "receive every alert", so upgrading
does not silence anything.

Revision ID: 0006
Revises: 0005
Create Date: 2026-07-28
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    columns = {c["name"] for c in sa.inspect(bind).get_columns("notification_channels")}
    if "alert_types" not in columns:
        op.add_column("notification_channels", sa.Column("alert_types", postgresql.JSONB))


def downgrade() -> None:
    op.drop_column("notification_channels", "alert_types")
