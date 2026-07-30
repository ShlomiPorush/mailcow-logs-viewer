"""Add security_alerts table (anomaly detection).

Revision ID: 0002
Revises: 0001
Create Date: 2026-07-13
"""
from alembic import op
import sqlalchemy as sa


revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Idempotent: pre-existing installs never had this table, but guard anyway
    bind = op.get_bind()
    if bind.dialect.has_table(bind, "security_alerts"):
        return

    op.create_table(
        "security_alerts",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("alert_type", sa.String(40), nullable=False),
        sa.Column("severity", sa.String(20), server_default="warning"),
        sa.Column("subject", sa.String(255)),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("detail", sa.Text),
        sa.Column("metric_value", sa.Float),
        sa.Column("baseline_value", sa.Float),
        sa.Column("acknowledged", sa.Boolean, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime),
    )
    op.create_index("ix_security_alerts_alert_type", "security_alerts", ["alert_type"])
    op.create_index("ix_security_alerts_severity", "security_alerts", ["severity"])
    op.create_index("ix_security_alerts_acknowledged", "security_alerts", ["acknowledged"])
    op.create_index("idx_security_alert_type_subject", "security_alerts", ["alert_type", "subject"])
    op.create_index("idx_security_alert_created", "security_alerts", ["created_at"])


def downgrade() -> None:
    op.drop_table("security_alerts")
