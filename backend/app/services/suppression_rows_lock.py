"""One writer of the suppression rows at a time.

The two-way sync with Rspamd decides from the rows what was deleted or added
in mailcow. Every job and request that changes the rows takes this lock first
in its transaction, so the sync never decides from rows another writer is
changing, and two runs that store stuck messages never both find one not yet
kept. A PostgreSQL advisory lock: held until the transaction ends, across
processes.

Order: the Rspamd map lock (services/rspamd_map_lock) first, then this one.
Nothing that holds this lock waits for the map lock.
"""
from sqlalchemy import text

# The key the stuck-message store held before; the same serialization
SUPPRESSION_ROWS_LOCK = 0x4D4C5601


def lock_suppression_rows(db) -> None:
    db.execute(text('SELECT pg_advisory_xact_lock(:key)'), {'key': SUPPRESSION_ROWS_LOCK})
