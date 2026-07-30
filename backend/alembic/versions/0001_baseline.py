"""Baseline - marks the pre-Alembic schema state (v2.6.3).

This revision is intentionally a no-op. The schema up to v2.6.3 is created by
`Base.metadata.create_all()` (app/database.py:init_db) plus the legacy
idempotent migrations in app/migrations.py, both of which still run on every
startup. Alembic starts tracking from this point:

- Existing installs: upgrade to head just records the baseline (nothing runs).
- Fresh installs: create_all + legacy migrations build the schema first, then
  Alembic records the baseline the same way.

From v2.6.4 onward, ALL new schema changes must be Alembic revisions in this
directory (see backend/alembic/README.md). app/migrations.py is frozen.

Revision ID: 0001
Revises:
Create Date: 2026-07-13
"""

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
