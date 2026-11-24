from sqlalchemy import text

SUPPRESSION_ROWS_LOCK = 0x4D4C5601


def lock_suppression_rows(db) -> None:
    db.execute(text('SELECT pg_advisory_xact_lock(:key)'), {'key': SUPPRESSION_ROWS_LOCK})
