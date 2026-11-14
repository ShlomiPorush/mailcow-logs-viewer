"""Security alerts remember which dismissal changed them, so it can be undone.

Adds security_alerts.ack_batch: the receipt of the acknowledgement that set
acknowledged on that row (one receipt for a Dismiss all). Undo by receipt
re-opens exactly those rows and nothing a later dismissal changed. Existing
acknowledged alerts keep no receipt: there is nothing to undo for them.

Revision ID: 0020
Revises: 0019
Create Date: 2026-10-22
"""
from alembic import op
import sqlalchemy as sa


revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # A fresh install creates the table from the model, column and index included
    inspector = sa.inspect(op.get_bind())
    if "ack_batch" not in {c["name"] for c in inspector.get_columns("security_alerts")}:
        op.add_column("security_alerts", sa.Column("ack_batch", sa.Uuid(), nullable=True))
    if "ix_security_alerts_ack_batch" not in {i["name"] for i in inspector.get_indexes("security_alerts")}:
        op.create_index("ix_security_alerts_ack_batch", "security_alerts", ["ack_batch"])


def downgrade() -> None:
    op.drop_index("ix_security_alerts_ack_batch", table_name="security_alerts")
    op.drop_column("security_alerts", "ack_batch")
