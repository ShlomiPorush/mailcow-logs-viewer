"""Add tlsa_check column for DANE/TLSA results (issue #72).

Revision ID: 0005
Revises: 0004
Create Date: 2026-07-28
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    columns = {c["name"] for c in sa.inspect(bind).get_columns("domain_dns_checks")}
    if "tlsa_check" not in columns:
        op.add_column("domain_dns_checks", sa.Column("tlsa_check", postgresql.JSONB))


def downgrade() -> None:
    op.drop_column("domain_dns_checks", "tlsa_check")
