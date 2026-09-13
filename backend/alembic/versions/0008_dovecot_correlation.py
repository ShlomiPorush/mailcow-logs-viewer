"""Add Dovecot delivery verdict to message correlations (issue #65).

Postfix logs only report that a message was handed to Dovecot over LMTP, so a
message dropped by a Sieve ``discard`` rule was shown as delivered. These
columns hold the outcome of that last hop.

Existing rows keep NULL, which reads as "no Dovecot information", so upgrading
changes nothing about how already-correlated messages are displayed.

Revision ID: 0008
Revises: 0007
Create Date: 2026-09-13
"""
from alembic import op
import sqlalchemy as sa


revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    columns = {c["name"] for c in sa.inspect(bind).get_columns("message_correlations")}

    if "dovecot_status" not in columns:
        op.add_column("message_correlations", sa.Column("dovecot_status", sa.String(30)))
        op.create_index(
            "ix_message_correlations_dovecot_status",
            "message_correlations",
            ["dovecot_status"],
        )
    if "dovecot_mailbox" not in columns:
        op.add_column("message_correlations", sa.Column("dovecot_mailbox", sa.String(255)))
    if "dovecot_detail" not in columns:
        op.add_column("message_correlations", sa.Column("dovecot_detail", sa.Text))


def downgrade() -> None:
    op.drop_index("ix_message_correlations_dovecot_status", table_name="message_correlations")
    op.drop_column("message_correlations", "dovecot_detail")
    op.drop_column("message_correlations", "dovecot_mailbox")
    op.drop_column("message_correlations", "dovecot_status")
