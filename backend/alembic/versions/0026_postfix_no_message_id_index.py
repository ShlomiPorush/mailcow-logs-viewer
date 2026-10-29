"""Index the Postfix cleanup lines that carry no usable Message-ID.

GET /api/messages/without-message-id (and the button on the Messages page that
asks it every 30 seconds) looks for the cleanup lines whose message-id field
holds no ID. Without an index that reads every Postfix line: about 115 ms on
5 million lines, more on a bigger server. The index holds only the cleanup
lines without a Message-ID, a handful, so it is small and quick to build.

A new install already has it (create_all builds it from the model before the
migrations run), so it is created only when missing.
"""
from alembic import op
import sqlalchemy as sa


revision = "0026"
down_revision = "0025"
branch_labels = None
depends_on = None

INDEX = "idx_postfix_cleanup_no_message_id"
WHERE = "message_id IS NULL AND program LIKE '%/cleanup'"


def _has_index(bind) -> bool:
    return INDEX in {index["name"] for index in sa.inspect(bind).get_indexes("postfix_logs")}


def upgrade() -> None:
    bind = op.get_bind()
    if not _has_index(bind):
        op.create_index(INDEX, "postfix_logs", ["time"], postgresql_where=sa.text(WHERE))


def downgrade() -> None:
    bind = op.get_bind()
    if _has_index(bind):
        op.drop_index(INDEX, table_name="postfix_logs")
