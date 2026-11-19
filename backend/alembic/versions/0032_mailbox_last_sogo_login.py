"""Keep the last SOGo login of a mailbox.

Since mailcow 2026-11a every mailbox has last_sogo_login: the last sign-in
through SOGo (webmail, and phones that sync through SOGo). Adds
mailbox_statistics.last_sogo_login, empty until the next mailbox sync.

The fresh-install start creates the column from the models first, so it is
only added when missing.

Revision ID: 0032
Revises: 0031
Create Date: 2026-11-19
"""
from alembic import op
import sqlalchemy as sa


revision = "0032"
down_revision = "0031"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if "last_sogo_login" not in {c["name"] for c in sa.inspect(op.get_bind()).get_columns("mailbox_statistics")}:
        op.add_column("mailbox_statistics", sa.Column("last_sogo_login", sa.BigInteger(), nullable=True))


def downgrade() -> None:
    op.drop_column("mailbox_statistics", "last_sogo_login")
