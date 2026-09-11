"""Add mta_sts_check column for MTA-STS results (issue #83).

Revision ID: 0007
Revises: 0006
Create Date: 2026-09-11
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    columns = {c["name"] for c in sa.inspect(bind).get_columns("domain_dns_checks")}
    if "mta_sts_check" not in columns:
        op.add_column("domain_dns_checks", sa.Column("mta_sts_check", postgresql.JSONB))


def downgrade() -> None:
    op.drop_column("domain_dns_checks", "mta_sts_check")
