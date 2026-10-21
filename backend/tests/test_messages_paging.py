"""Messages pages: addresses hidden with Blacklist Emails are left out by the
query, so a page is never empty while messages follow and the total counts
only what can be shown; the next page starts after the last message shown (a
cursor), so a message removed in between skips nothing."""
import uuid
from datetime import datetime, timedelta

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app.config import settings

MARK = uuid.uuid4().hex[:8]
SENDER = f'paging-{MARK}@example.com'
HIDDEN = f'hidden-{MARK}@example.net'


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


@pytest.fixture()
def client(monkeypatch):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    for key in ('auth_enabled', 'basic_auth_enabled', 'oauth2_enabled'):
        monkeypatch.setattr(settings._inner, key, False)
    monkeypatch.setattr(settings._inner, 'blacklist_emails', HIDDEN.upper())
    from app.database import init_db, get_db_context
    from app.models import MessageCorrelation
    init_db()

    def cleanup():
        with get_db_context() as db:
            db.query(MessageCorrelation).filter(MessageCorrelation.sender == SENDER).delete(synchronize_session=False)
            db.commit()
    cleanup()
    now = datetime.utcnow().replace(microsecond=0)
    with get_db_context() as db:
        # The newest five go to the hidden address; ten shown ones follow
        for minute in range(15):
            db.add(MessageCorrelation(correlation_key=uuid.uuid4().hex, sender=SENDER,
                                      recipient=HIDDEN if minute < 5 else f'r{minute}@example.org',
                                      direction='outbound', subject=f'm{minute:02d} {MARK}', final_status='delivered',
                                      first_seen=now - timedelta(minutes=minute), last_seen=now, created_at=now))
        db.commit()
    from fastapi.testclient import TestClient
    from app.main import app
    yield TestClient(app)
    cleanup()


def _page(client, query):
    response = client.get(f'/api/messages?search={SENDER}&{query}')
    assert response.status_code == 200, response.text
    return response.json()


def _subjects(page):
    return [m['subject'].split()[0] for m in page['data']]


def test_hidden_addresses_leave_no_empty_page_and_no_count(client):
    first = _page(client, 'limit=3')
    assert _subjects(first) == ['m05', 'm06', 'm07']
    assert first['total'] == 10
    facets = client.get(f'/api/messages/facets?search={SENDER}').json()
    assert facets['status']['all'] == 10, facets


def test_pages_follow_the_cursor_to_the_end(client):
    seen, cursor = [], None
    while True:
        page = _page(client, 'limit=4' + (f'&cursor={cursor}' if cursor else ''))
        seen += _subjects(page)
        cursor = page['next_cursor']
        if not cursor:
            break
    assert seen == [f'm{n:02d}' for n in range(5, 15)]


def test_a_message_removed_between_pages_skips_nothing(client):
    from app.database import get_db_context
    from app.models import MessageCorrelation
    first = _page(client, 'order=asc&limit=4')
    assert _subjects(first) == ['m14', 'm13', 'm12', 'm11']
    # Retention removes the oldest one shown before the next page is asked for
    with get_db_context() as db:
        db.query(MessageCorrelation).filter(MessageCorrelation.subject == f'm14 {MARK}').delete(synchronize_session=False)
        db.commit()
    second = _page(client, f'order=asc&limit=4&cursor={first["next_cursor"]}')
    assert _subjects(second) == ['m10', 'm09', 'm08', 'm07']


def test_a_bad_cursor_is_refused(client):
    assert client.get('/api/messages?cursor=yesterday').status_code == 422


def test_an_address_stored_with_whitespace_around_it_stays_hidden(client):
    from app.database import get_db_context
    from app.models import MessageCorrelation
    now = datetime.utcnow().replace(microsecond=0)
    with get_db_context() as db:
        db.add(MessageCorrelation(correlation_key=uuid.uuid4().hex, sender=SENDER, recipient=f'\t{HIDDEN}\r\n',
                                  direction='outbound', subject=f'padded {MARK}', final_status='delivered',
                                  first_seen=now, last_seen=now, created_at=now))
        db.commit()
    page = _page(client, 'limit=50')
    assert 'padded' not in _subjects(page) and page['total'] == 10


def test_a_message_without_a_first_seen_time_has_its_place(client):
    from app.database import get_db_context
    from app.models import MessageCorrelation
    now = datetime.utcnow().replace(microsecond=0)
    with get_db_context() as db:
        db.add(MessageCorrelation(correlation_key=uuid.uuid4().hex, sender=SENDER, recipient='late@example.org',
                                  direction='outbound', subject=f'unseen {MARK}', final_status='delivered',
                                  first_seen=None, last_seen=now, created_at=now - timedelta(seconds=390)))
        db.commit()
    for order, expected in (('desc', ['m05', 'm06', 'unseen', 'm07']), ('asc', ['m14', 'm13', 'm12', 'm11'])):
        seen, cursor = [], None
        while True:
            page = _page(client, f'order={order}&limit=1' + (f'&cursor={cursor}' if cursor else ''))
            seen += _subjects(page)
            cursor = page['next_cursor']
            if not cursor:
                break
        assert seen[:4] == expected and len(seen) == 11 and 'unseen' in seen, (order, seen)
