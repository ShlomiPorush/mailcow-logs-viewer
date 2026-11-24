from sqlalchemy import text

# Taking the Rspamd map lock after this one can deadlock.
SUPPRESSION_ROWS_LOCK = 0x4D4C5601


def lock_suppression_rows(db) -> None:
    db.execute(text('SELECT pg_advisory_xact_lock(:key)'), {'key': SUPPRESSION_ROWS_LOCK})
