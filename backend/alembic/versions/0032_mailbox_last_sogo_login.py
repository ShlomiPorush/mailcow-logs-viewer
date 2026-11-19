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


revision = "0032"
down_revision = "0031"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE mailbox_statistics ADD COLUMN IF NOT EXISTS last_sogo_login BIGINT")


def downgrade() -> None:
    op.drop_column("mailbox_statistics", "last_sogo_login")
