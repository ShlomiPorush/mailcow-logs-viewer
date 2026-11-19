"""Agent access: agents that connect with a code a person approves (RFC 8628).

Creates agent_device_requests. The app's start creates it from the models first
on a fresh install, so the table and its indexes are only created when missing.

Revision ID: 0023
Revises: 0022
Create Date: 2026-10-24
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


revision = "0023"
down_revision = "0022"
branch_labels = None
depends_on = None


def _index(bind, table, name, columns, unique=False):
    if name not in {i["name"] for i in sa.inspect(bind).get_indexes(table)}:
        op.create_index(name, table, columns, unique=unique)


def upgrade() -> None:
    bind = op.get_bind()
    if "agent_device_requests" not in set(sa.inspect(bind).get_table_names()):
        op.create_table(
            "agent_device_requests",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("device_code_hash", sa.String(64), nullable=False, unique=True),
            sa.Column("user_code", sa.String(8), nullable=False),
            sa.Column("client_id", sa.String(64), nullable=False),
            sa.Column("label", sa.String(100), nullable=False),
            sa.Column("requested", sa.Text, nullable=False),
            sa.Column("resource", sa.String(512), nullable=False),
            sa.Column("state", sa.String(10), nullable=False),
            sa.Column("created_at", sa.DateTime, nullable=False),
            sa.Column("expires_at", sa.DateTime, nullable=False),
            sa.Column("interval", sa.Integer, nullable=False),
            sa.Column("last_poll_at", sa.DateTime),
            sa.Column("details", JSONB),
            sa.Column("answered_at", sa.DateTime),
            sa.Column("grant_id", sa.Integer, sa.ForeignKey("agent_grants.id", ondelete="SET NULL")),
        )
    _index(bind, "agent_device_requests", "ix_agent_device_requests_user_code", ["user_code"])
    _index(bind, "agent_device_requests", "ix_agent_device_requests_expires_at", ["expires_at"])


def downgrade() -> None:
    op.drop_table("agent_device_requests")
