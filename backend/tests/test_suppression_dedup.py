"""Regression for issue seen in the Detect Suppressions job: a recipient
bouncing several times within one scan batch caused duplicate INSERTs for
the same email (unique index violation) because the session has
autoflush=False and pending entries are invisible to queries."""
import asyncio
from datetime import datetime

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def test_repeated_bounces_in_one_batch_create_single_suppression(monkeypatch):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import init_db, get_db_context
    from app.models import PostfixLog, SpamSuppression
    from app.config import settings
    import app.scheduler as sch

    init_db()
    monkeypatch.setattr(settings._inner, 'suppression_enabled', True)
    monkeypatch.setattr(settings._inner, 'suppression_auto_detect', False)

    email = 'dedup-test@bounce.example'
    with get_db_context() as db:
        db.query(SpamSuppression).filter(SpamSuppression.email == email).delete()
        db.query(PostfixLog).filter(PostfixLog.recipient == email).delete()
        for i in range(3):
            db.add(PostfixLog(time=datetime.utcnow(), created_at=datetime.utcnow(),
                              program='postfix/smtp', priority='info',
                              message=f'bounce {i}', queue_id=f'Q{i}DEDUP',
                              recipient=email, status='bounced', dsn='5.4.4'))
        db.commit()

    monkeypatch.setattr(settings._inner, 'suppression_auto_detect', True)
    monkeypatch.setattr(settings._inner, 'suppression_rspamd_sync', False)
    asyncio.run(sch.detect_suppressions_job())

    with get_db_context() as db:
        rows = db.query(SpamSuppression).filter(SpamSuppression.email == email).all()
        assert len(rows) == 1, f"expected one suppression row, got {len(rows)}"
        assert rows[0].bounce_count == 3
        assert rows[0].hard_bounce_count == 3
        db.query(SpamSuppression).filter(SpamSuppression.email == email).delete()
        db.query(PostfixLog).filter(PostfixLog.recipient == email).delete()
        db.commit()
