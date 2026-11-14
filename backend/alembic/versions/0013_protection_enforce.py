"""Protection hits can ban: when, until when, whether the app added the entry.

Revision ID: 0013
Revises: 0012
Create Date: 2026-09-30
"""
from alembic import op
import sqlalchemy as sa


revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None

_COLUMNS = (
    ("ban_hours", sa.Integer),
    ("banned_at", sa.DateTime),
    ("expires_at", sa.DateTime),
    ("owned", sa.Boolean),
    ("error", sa.Text),
)


def upgrade() -> None:
    # A fresh install creates the table from the model, columns and index included
    inspector = sa.inspect(op.get_bind())
    existing = {c["name"] for c in inspector.get_columns("protection_hits")}
    for name, kind in _COLUMNS:
        if name not in existing:
            op.add_column("protection_hits", sa.Column(name, kind))
    if "ix_protection_hits_expires_at" not in {i["name"] for i in inspector.get_indexes("protection_hits")}:
        op.create_index("ix_protection_hits_expires_at", "protection_hits", ["expires_at"])


def downgrade() -> None:
    op.drop_index("ix_protection_hits_expires_at", table_name="protection_hits")
    for name, _ in _COLUMNS:
        op.drop_column("protection_hits", name)
