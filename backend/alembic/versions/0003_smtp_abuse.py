"""Add SMTP abuse protection tables (whitelist + action audit trail).

Revision ID: 0003
Revises: 0002
Create Date: 2026-07-14
"""
from alembic import op
import sqlalchemy as sa


revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = set(inspector.get_table_names())

    if "smtp_abuse_whitelist" not in existing:
        op.create_table(
            "smtp_abuse_whitelist",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("email", sa.String(255), nullable=False, unique=True),
            sa.Column("notes", sa.Text),
            sa.Column("active", sa.Boolean, nullable=False, server_default=sa.true()),
            sa.Column("created_at", sa.DateTime, nullable=False),
            sa.Column("updated_at", sa.DateTime),
        )
        op.create_index("ix_smtp_abuse_whitelist_email", "smtp_abuse_whitelist", ["email"], unique=True)
        op.create_index("ix_smtp_abuse_whitelist_active", "smtp_abuse_whitelist", ["active"])

    if "smtp_abuse_actions" not in existing:
        op.create_table(
            "smtp_abuse_actions",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("email", sa.String(255), nullable=False),
            sa.Column("message_count", sa.Integer, nullable=False),
            sa.Column("threshold", sa.Integer, nullable=False),
            sa.Column("window_minutes", sa.Integer, nullable=False),
            sa.Column("action", sa.String(30), nullable=False, server_default="blocked"),
            sa.Column("automatic", sa.Boolean, nullable=False, server_default=sa.true()),
            sa.Column("operator", sa.String(255)),
            sa.Column("app_passwords_revoked", sa.Integer, server_default="0"),
            sa.Column("created_at", sa.DateTime, nullable=False),
        )
        op.create_index("ix_smtp_abuse_actions_email", "smtp_abuse_actions", ["email"])
        op.create_index("ix_smtp_abuse_actions_created_at", "smtp_abuse_actions", ["created_at"])
        op.create_index("idx_smtp_abuse_email_created", "smtp_abuse_actions", ["email", "created_at"])


def downgrade() -> None:
    op.drop_table("smtp_abuse_actions")
    op.drop_table("smtp_abuse_whitelist")
