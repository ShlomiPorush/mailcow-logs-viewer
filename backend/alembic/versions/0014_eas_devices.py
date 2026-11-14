"""ActiveSync devices seen in SOGo's access log.

Revision ID: 0014
Revises: 0013
Create Date: 2026-10-05
"""
from alembic import op
import sqlalchemy as sa


revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # A fresh install creates the table from the model
    if "eas_devices" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "eas_devices",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("username", sa.String(255), nullable=False),
        sa.Column("device_id", sa.String(255), nullable=False),
        sa.Column("device_type", sa.String(100)),
        sa.Column("last_ip", sa.String(255)),
        sa.Column("last_command", sa.String(64)),
        sa.Column("last_status", sa.Integer),
        sa.Column("first_seen", sa.DateTime, nullable=False),
        sa.Column("last_seen", sa.DateTime, nullable=False),
        sa.UniqueConstraint("username", "device_id", name="uq_eas_device"),
    )
    op.create_index("ix_eas_devices_id", "eas_devices", ["id"])
    op.create_index("idx_eas_device_last_seen", "eas_devices", ["last_seen"])


def downgrade() -> None:
    op.drop_table("eas_devices")
