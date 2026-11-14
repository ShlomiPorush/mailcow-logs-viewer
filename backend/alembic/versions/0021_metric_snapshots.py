"""Hourly samples of the dashboard figures that show a trend.

Creates metric_snapshots: one row per figure and hour (name, slot), its value
and denominator, and when it was read. The app's start creates it from the
model first on a fresh install, so this only fills the gap. Rows of a feature
that is off are deleted with the feature's data; all are kept 90 days.

Revision ID: 0021
Revises: 0020
Create Date: 2026-10-22
"""
from alembic import op
import sqlalchemy as sa


revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if "metric_snapshots" not in sa.inspect(bind).get_table_names():
        op.create_table(
            "metric_snapshots",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("name", sa.String(40), nullable=False),
            sa.Column("slot", sa.DateTime, nullable=False),
            sa.Column("value", sa.Float),
            sa.Column("of", sa.Float),
            sa.Column("as_of", sa.DateTime, nullable=False),
            sa.UniqueConstraint("name", "slot", name="uq_metric_snapshot_name_slot"),
        )
    if "idx_metric_snapshot_slot" not in {i["name"] for i in sa.inspect(bind).get_indexes("metric_snapshots")}:
        op.create_index("idx_metric_snapshot_slot", "metric_snapshots", ["slot"])


def downgrade() -> None:
    op.drop_table("metric_snapshots")
