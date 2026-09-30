"""Add tls_rpt_check column for TLS-RPT record results (issue #328).

Revision ID: 0011
Revises: 0010
Create Date: 2026-09-30
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    columns = {c["name"] for c in sa.inspect(bind).get_columns("domain_dns_checks")}
    if "tls_rpt_check" not in columns:
        op.add_column("domain_dns_checks", sa.Column("tls_rpt_check", postgresql.JSONB))


def downgrade() -> None:
    op.drop_column("domain_dns_checks", "tls_rpt_check")
