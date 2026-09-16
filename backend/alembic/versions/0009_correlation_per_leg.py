"""One correlation per delivery leg, not per Message-ID (issue #36).

A forward, a Sieve redirect or any other re-submission delivers the same
Message-ID through a second Postfix queue chain. While message_id was UNIQUE
the second leg overwrote the first one, so the original delivery disappeared
from the Messages list. Each leg now gets its own row, keyed by
(Message-ID, queue chain), and the uniqueness has to go.

The unique may exist as an index (SQLAlchemy's Column(unique=True, index=True)
creates ix_message_correlations_message_id as a UNIQUE INDEX) or, on databases
built by an older path, as a table constraint. Both shapes are handled, and a
database that never had either is left alone.

Historical rows that were merged under the old behaviour are left as they are:
the overwritten leg was never stored, so there is nothing to restore.

Revision ID: 0009
Revises: 0008
Create Date: 2026-09-13
"""
from alembic import op
import sqlalchemy as sa


revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None

TABLE = "message_correlations"
UNIQUE_INDEX = "ix_message_correlations_message_id"
PLAIN_INDEX = "idx_correlation_message_id"


def _index_names(bind) -> set:
    rows = bind.execute(
        sa.text("SELECT indexname FROM pg_indexes WHERE tablename = :t"),
        {"t": TABLE},
    )
    return {row[0] for row in rows}


def _unique_constraint_names(bind) -> set:
    rows = bind.execute(
        sa.text(
            "SELECT con.conname FROM pg_constraint con "
            "JOIN pg_class rel ON rel.oid = con.conrelid "
            "WHERE rel.relname = :t AND con.contype = 'u'"
        ),
        {"t": TABLE},
    )
    return {row[0] for row in rows}


def _is_unique_index(bind, name: str) -> bool:
    row = bind.execute(
        sa.text(
            "SELECT idx.indisunique FROM pg_index idx "
            "JOIN pg_class ic ON ic.oid = idx.indexrelid "
            "JOIN pg_class tc ON tc.oid = idx.indrelid "
            "WHERE tc.relname = :t AND ic.relname = :i"
        ),
        {"t": TABLE, "i": name},
    ).first()
    return bool(row and row[0])


def upgrade() -> None:
    bind = op.get_bind()

    # A unique constraint owns its index, so it has to be dropped as a
    # constraint; dropping the index directly would fail.
    for name in _unique_constraint_names(bind):
        cols = bind.execute(
            sa.text(
                "SELECT a.attname FROM pg_constraint con "
                "JOIN pg_class rel ON rel.oid = con.conrelid "
                "JOIN unnest(con.conkey) AS k(attnum) ON TRUE "
                "JOIN pg_attribute a ON a.attrelid = rel.oid AND a.attnum = k.attnum "
                "WHERE rel.relname = :t AND con.conname = :c"
            ),
            {"t": TABLE, "c": name},
        ).fetchall()
        if [c[0] for c in cols] == ["message_id"]:
            op.drop_constraint(name, TABLE, type_="unique")

    indexes = _index_names(bind)
    if UNIQUE_INDEX in indexes and _is_unique_index(bind, UNIQUE_INDEX):
        op.drop_index(UNIQUE_INDEX, table_name=TABLE)
        indexes.discard(UNIQUE_INDEX)

    # Lookups by Message-ID stay hot (the Dovecot job and the related-deliveries
    # list both use them), so a plain index must remain.
    indexes = _index_names(bind)
    if PLAIN_INDEX not in indexes and UNIQUE_INDEX not in indexes:
        op.create_index(PLAIN_INDEX, TABLE, ["message_id"])


def downgrade() -> None:
    # Re-creating the unique index can only succeed when no message has more
    # than one delivery leg, which is exactly what this revision allows. The
    # extra legs are removed first, keeping the first-created one of each
    # Message-ID (id order, which never contains NULLs).
    bind = op.get_bind()
    bind.execute(sa.text(
        "DELETE FROM message_correlations mc USING message_correlations keep "
        "WHERE mc.message_id IS NOT NULL AND mc.message_id = keep.message_id "
        "AND keep.id < mc.id"
    ))
    if UNIQUE_INDEX not in _index_names(bind):
        op.create_index(UNIQUE_INDEX, TABLE, ["message_id"], unique=True)
