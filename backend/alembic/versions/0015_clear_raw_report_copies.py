"""Clear the stored original copies of DMARC and TLS-RPT reports.

Nothing ever read dmarc_reports.raw_xml or tls_reports.raw_json, and the app
no longer writes them. The parsed reports stay untouched. The columns are
kept (nullable) so an older version still runs against this database.

Postgres reuses the freed space for new rows; autovacuum reclaims it over
time, so no VACUUM is run here (it cannot run inside the migration's
transaction anyway).

Revision ID: 0015
Revises: 0014
Create Date: 2026-10-08
"""
from alembic import op


revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # One statement per table; any error aborts the migration and startup
    op.execute("UPDATE dmarc_reports SET raw_xml = NULL WHERE raw_xml IS NOT NULL")
    op.execute("UPDATE tls_reports SET raw_json = NULL WHERE raw_json IS NOT NULL")


def downgrade() -> None:
    # The cleared copies cannot be restored; the columns themselves remain
    pass
