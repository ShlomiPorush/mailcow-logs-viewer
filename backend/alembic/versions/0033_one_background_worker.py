"""Run the background jobs in one container only.

Revision ID: 0033
Revises: 0032
Create Date: 2026-11-26
"""
from alembic import op
import sqlalchemy as sa


revision = "0033"
down_revision = "0032"
branch_labels = None
depends_on = None

downtime = True


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())

    if "postfix_logs" in tables and not bind.execute(sa.text(
            "SELECT 1 FROM pg_indexes WHERE tablename = 'postfix_logs' AND indexname = 'uq_postfix_log'")).first():
        op.execute("""
            DELETE FROM postfix_logs
            WHERE id IN (
                SELECT id FROM (
                    SELECT id, ROW_NUMBER() OVER (
                        PARTITION BY time, program, COALESCE(queue_id, ''), message
                        ORDER BY created_at ASC
                    ) AS row_num
                    FROM postfix_logs
                ) ranked
                WHERE ranked.row_num > 1
            )
        """)
        op.execute("CREATE UNIQUE INDEX uq_postfix_log ON postfix_logs (time, program, COALESCE(queue_id, ''), message)")

    if "monitored_hosts" in tables:
        length = bind.execute(sa.text(
            "SELECT character_maximum_length FROM information_schema.columns "
            "WHERE table_name = 'monitored_hosts' AND column_name = 'source'")).scalar()
        if length is not None:
            op.execute("ALTER TABLE monitored_hosts ALTER COLUMN source TYPE TEXT")


def downgrade() -> None:
    pass
