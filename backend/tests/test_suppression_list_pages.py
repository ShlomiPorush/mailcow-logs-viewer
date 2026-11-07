"""The suppression list loads page after page as it scrolls, so the pages of
one sort must neither repeat nor miss a row, also among rows that sort equal.

Fictional addresses only."""
import uuid
from datetime import datetime

import pytest

# init_db creates the tables of the models imported so far
import app.models  # noqa: F401

MARK = uuid.uuid4().hex[:8]
ROWS, PER_PAGE = 120, 9


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


@pytest.fixture
def rows():
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import get_db_context, init_db
    from app.models import SpamSuppression
    init_db()
    same = datetime(2026, 1, 1, 12, 0, 0)
    with get_db_context() as db:
        for i in range(ROWS):
            db.add(SpamSuppression(email=f'tie{i}-{MARK}@example.net', type='email', reason='manual', source='manual',
                                   bounce_count=2, hard_bounce_count=2, soft_bounce_count=0, active=True,
                                   synced_to_rspamd=True, created_at=same, updated_at=same))
        db.commit()
    yield
    with get_db_context() as db:
        db.query(SpamSuppression).filter(SpamSuppression.email.like(f'%{MARK}%')).delete(synchronize_session=False)
        db.commit()


@pytest.mark.parametrize('sort_by', ['created_at', 'bounce_count', 'reason', 'expires_at'])
@pytest.mark.parametrize('sort_dir', ['asc', 'desc'])
def test_pages_of_rows_that_sort_equal_show_each_row_once(rows, sort_by, sort_dir):
    from app.database import get_db_context
    from app.routers.suppressions import list_suppressions
    seen = []
    with get_db_context() as db:
        for page in range(1, -(-ROWS // PER_PAGE) + 1):
            data = list_suppressions(db=db, page=page, per_page=PER_PAGE, search=MARK, type_filter=None, reason_filter=None,
                                     active_filter=None, sort_by=sort_by, sort_dir=sort_dir)
            seen += [item['email'] for item in data['items']]
    assert len(seen) == ROWS
    assert len(set(seen)) == ROWS
