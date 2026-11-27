"""Keep mailcow's "login disabled" state of a mailbox.

Since mailcow 2026-11 a mailbox can be active, inactive, or active with its
login disabled (active 2): it may not sign in, and its mail is still
delivered. Adds mailbox_statistics.login_disabled. The next mailbox sync, a
few minutes after the start, sets it and counts such a mailbox as active.

The fresh-install start creates the column from the models first, so it is
only added when missing.

Revision ID: 0031
Revises: 0030
Create Date: 2026-11-09
"""
from alembic import op
import sqlalchemy as sa


revision = "0031"
down_revision = "0030"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if "mailbox_statistics" not in set(sa.inspect(bind).get_table_names()):
        return
    if "login_disabled" not in {c["name"] for c in sa.inspect(bind).get_columns("mailbox_statistics")}:
        op.add_column("mailbox_statistics", sa.Column(
            "login_disabled", sa.Boolean(), nullable=False, server_default=sa.text("false")))


def downgrade() -> None:
    op.drop_column("mailbox_statistics", "login_disabled")
