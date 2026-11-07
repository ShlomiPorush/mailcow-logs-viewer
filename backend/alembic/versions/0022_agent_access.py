"""Agent access: connected AI agents, their tokens and what they did.

Creates agent_clients (programs that registered themselves), agent_grants (one
row per connected agent), agent_codes (authorization codes on their way to a
token), agent_tokens (access and refresh tokens, hashed) and agent_audit. The
app's start creates them from the models first on a fresh install, so each
table and index is only created when missing.

Revision ID: 0022
Revises: 0021
Create Date: 2026-10-23
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None


def _tables(bind):
    return set(sa.inspect(bind).get_table_names())


def _index(bind, table, name, columns, unique=False):
    if name not in {i["name"] for i in sa.inspect(bind).get_indexes(table)}:
        op.create_index(name, table, columns, unique=unique)


def upgrade() -> None:
    bind = op.get_bind()
    if "agent_clients" not in _tables(bind):
        op.create_table(
            "agent_clients",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("client_id", sa.String(64), nullable=False, unique=True),
            sa.Column("client_name", sa.String(100), nullable=False),
            sa.Column("redirect_uris", JSONB, nullable=False),
            sa.Column("created_at", sa.DateTime, nullable=False),
            sa.Column("created_ip", sa.String(64)),
            sa.Column("last_used_at", sa.DateTime),
        )
    if "agent_grants" not in _tables(bind):
        op.create_table(
            "agent_grants",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("client_id", sa.String(512), nullable=False),
            sa.Column("client_kind", sa.String(10), nullable=False),
            sa.Column("display_name", sa.String(100), nullable=False),
            sa.Column("declared_name", sa.String(100), nullable=False),
            sa.Column("publisher", sa.String(255)),
            sa.Column("redirect_uri", sa.String(512), nullable=False),
            sa.Column("scopes", sa.Text, nullable=False),
            sa.Column("resource", sa.String(512), nullable=False),
            sa.Column("approved_by", sa.String(255)),
            sa.Column("created_at", sa.DateTime, nullable=False),
            sa.Column("expires_at", sa.DateTime, nullable=False),
            sa.Column("last_used_at", sa.DateTime),
            sa.Column("revoked_at", sa.DateTime),
            sa.Column("revoke_reason", sa.String(40)),
        )
    _index(bind, "agent_grants", "ix_agent_grants_client_id", ["client_id"])
    _index(bind, "agent_grants", "ix_agent_grants_expires_at", ["expires_at"])
    _index(bind, "agent_grants", "ix_agent_grants_revoked_at", ["revoked_at"])
    if "agent_codes" not in _tables(bind):
        op.create_table(
            "agent_codes",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("code_hash", sa.String(64), nullable=False, unique=True),
            sa.Column("client_id", sa.String(512), nullable=False),
            sa.Column("redirect_uri", sa.String(512), nullable=False),
            sa.Column("code_challenge", sa.String(128), nullable=False),
            sa.Column("resource", sa.String(512), nullable=False),
            sa.Column("details", JSONB, nullable=False),
            sa.Column("created_at", sa.DateTime, nullable=False),
            sa.Column("expires_at", sa.DateTime, nullable=False),
            sa.Column("used_at", sa.DateTime),
            sa.Column("grant_id", sa.Integer, sa.ForeignKey("agent_grants.id", ondelete="CASCADE")),
        )
    _index(bind, "agent_codes", "ix_agent_codes_expires_at", ["expires_at"])
    if "agent_tokens" not in _tables(bind):
        op.create_table(
            "agent_tokens",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("grant_id", sa.Integer, sa.ForeignKey("agent_grants.id", ondelete="CASCADE"), nullable=False),
            sa.Column("kind", sa.String(10), nullable=False),
            sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
            sa.Column("client_id", sa.String(512), nullable=False),
            sa.Column("created_at", sa.DateTime, nullable=False),
            sa.Column("expires_at", sa.DateTime, nullable=False),
            sa.Column("rotated_at", sa.DateTime),
        )
    _index(bind, "agent_tokens", "ix_agent_tokens_grant_id", ["grant_id"])
    _index(bind, "agent_tokens", "ix_agent_tokens_expires_at", ["expires_at"])
    if "agent_audit" not in _tables(bind):
        op.create_table(
            "agent_audit",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("grant_id", sa.Integer, sa.ForeignKey("agent_grants.id", ondelete="SET NULL")),
            sa.Column("agent_name", sa.String(100)),
            sa.Column("at", sa.DateTime, nullable=False),
            sa.Column("event", sa.String(20), nullable=False),
            sa.Column("tool", sa.String(40)),
            sa.Column("method", sa.String(10)),
            sa.Column("path", sa.String(512)),
            sa.Column("http_status", sa.Integer),
            sa.Column("outcome", sa.String(10)),
            sa.Column("detail", sa.String(300)),
        )
    _index(bind, "agent_audit", "ix_agent_audit_grant_id", ["grant_id"])
    _index(bind, "agent_audit", "ix_agent_audit_at", ["at"])


def downgrade() -> None:
    for table in ("agent_audit", "agent_tokens", "agent_codes", "agent_grants", "agent_clients"):
        op.drop_table(table)
