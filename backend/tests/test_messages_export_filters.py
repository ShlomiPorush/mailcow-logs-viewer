"""The Messages CSV export applies the filters as the Messages list does: the
search also finds the client IP and the logged-in user, and the Spam outcome
also takes the messages Rspamd marked as spam. Addresses hidden with Blacklist
Emails stay hidden, and the rows come newest first as in the list."""
import csv
import io
import uuid
from datetime import datetime, timedelta

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app.config import settings

MARK = uuid.uuid4().hex[:8]
SENDER = f'export-{MARK}@example.com'
LOGIN = f'login-{MARK}@example.com'
IP = '203.0.113.77'
ARCHIVE = f"archive-{MARK}@example.net"


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
    from app.database import init_db, get_db_context
    from app.models import MessageCorrelation, RspamdLog
    init_db()

    def cleanup():
        with get_db_context() as db:
            db.query(MessageCorrelation).filter(MessageCorrelation.sender == SENDER).delete(synchronize_session=False)
            db.query(RspamdLog).filter(RspamdLog.sender_smtp == SENDER).delete(synchronize_session=False)
            db.commit()
    cleanup()
    now = datetime.utcnow().replace(microsecond=0)
    with get_db_context() as db:
        # Delivered, but Rspamd scored it as spam; sent by another login from a client IP
        scan = RspamdLog(time=now, sender_smtp=SENDER, is_spam=True, has_auth=True, user=LOGIN, ip=IP, direction='outbound')
        db.add(scan)
        db.flush()
        db.add(MessageCorrelation(correlation_key=uuid.uuid4().hex, sender=SENDER, recipient='rcpt@example.net',
                                  direction='outbound', subject=f'Report {MARK}', final_status='delivered',
                                  first_seen=now, last_seen=now, created_at=now, rspamd_log_id=scan.id))
        # Older but updated last: the list orders by first seen, so it comes after Newer
        for subject, recipient, first, last in ((f'Older {MARK}', 'a@example.net', 120, 0),
                                                (f'Newer {MARK}', 'b@example.net', 60, 60),
                                                (f'Archive {MARK}', ARCHIVE, 30, 30)):
            db.add(MessageCorrelation(correlation_key=uuid.uuid4().hex, sender=SENDER, recipient=recipient,
                                      direction='outbound', subject=subject, final_status='delivered',
                                      first_seen=now - timedelta(minutes=first), last_seen=now - timedelta(minutes=last),
                                      created_at=now))
        db.commit()
    from fastapi.testclient import TestClient
    from app.main import app
    yield TestClient(app)
    cleanup()


def _rows(response):
    assert response.status_code == 200, response.status_code
    return list(csv.DictReader(io.StringIO(response.content.decode('utf-8-sig'))))


def _list_total(client, query):
    return client.get(f'/api/messages?{query}').json()['total']


@pytest.mark.parametrize('query', [f'search={IP}', f'search={LOGIN}', f'status=spam&sender={SENDER}'])
def test_the_export_has_the_messages_the_list_shows(client, query):
    assert _list_total(client, query) >= 1
    rows = _rows(client.get(f'/api/export/messages/csv?{query}'))
    assert [r['Subject'] for r in rows if r['Sender'] == SENDER] == [f'Report {MARK}']


def test_the_export_orders_by_first_seen_as_the_list_does(client):
    subjects = [r['Subject'] for r in _rows(client.get(f'/api/export/messages/csv?sender={SENDER}'))]
    assert subjects == [f'Report {MARK}', f'Archive {MARK}', f'Newer {MARK}', f'Older {MARK}']


def test_the_export_leaves_out_hidden_addresses(client, monkeypatch):
    monkeypatch.setattr(settings._inner, 'blacklist_emails', ARCHIVE.upper())
    subjects = [r['Subject'] for r in _rows(client.get(f'/api/export/messages/csv?sender={SENDER}'))]
    assert f'Archive {MARK}' not in subjects and f'Newer {MARK}' in subjects
