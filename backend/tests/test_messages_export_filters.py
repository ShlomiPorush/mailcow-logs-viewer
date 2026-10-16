"""The Messages CSV export applies the filters as the Messages list does: the
search also finds the client IP and the logged-in user, and the Spam outcome
also takes the messages Rspamd marked as spam."""
import csv
import io
import uuid
from datetime import datetime

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app.config import settings

MARK = uuid.uuid4().hex[:8]
SENDER = f'export-{MARK}@example.com'
LOGIN = f'login-{MARK}@example.com'
IP = '203.0.113.77'


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
