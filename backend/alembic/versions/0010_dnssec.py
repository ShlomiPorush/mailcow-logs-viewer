"""Add dnssec_check column for DNSSEC results (issue #287).

Revision ID: 0010
Revises: 0009
Create Date: 2026-09-28
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    columns = {c["name"] for c in sa.inspect(bind).get_columns("domain_dns_checks")}
    if "dnssec_check" not in columns:
        op.add_column("domain_dns_checks", sa.Column("dnssec_check", postgresql.JSONB))


def downgrade() -> None:
    op.drop_column("domain_dns_checks", "dnssec_check")
