"""Add the protection_hits table for protection rules.

Revision ID: 0012
Revises: 0011
Create Date: 2026-09-30
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if "protection_hits" in set(sa.inspect(bind).get_table_names()):
        return
    op.create_table(
        "protection_hits",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("ip", sa.String(50), nullable=False),
        sa.Column("rule", sa.String(40), nullable=False),
        sa.Column("mode", sa.String(20), nullable=False, server_default="watch"),
        sa.Column("status", sa.String(20), nullable=False, server_default="watching"),
        sa.Column("reason", sa.Text),
        sa.Column("usernames", postgresql.JSONB),
        sa.Column("log_ids", postgresql.JSONB),
        sa.Column("attempts", sa.Integer, nullable=False, server_default="0"),
        sa.Column("country_code", sa.String(2)),
        sa.Column("country_name", sa.String(100)),
        sa.Column("first_seen", sa.DateTime, nullable=False),
        sa.Column("last_seen", sa.DateTime, nullable=False),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("ended_at", sa.DateTime),
    )
    op.create_index("ix_protection_hits_id", "protection_hits", ["id"])
    op.create_index("ix_protection_hits_ip", "protection_hits", ["ip"])
    op.create_index("ix_protection_hits_rule", "protection_hits", ["rule"])
    op.create_index("ix_protection_hits_status", "protection_hits", ["status"])
    op.create_index("ix_protection_hits_last_seen", "protection_hits", ["last_seen"])
    op.create_index("idx_protection_hits_ip_rule_status", "protection_hits", ["ip", "rule", "status"])


def downgrade() -> None:
    op.drop_table("protection_hits")
