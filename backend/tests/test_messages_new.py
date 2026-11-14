"""New mail for the Messages list: the list comes with a watermark (the newest
delivery stored), and GET /api/messages/new counts the messages matching the
filters that came after it. A message that was there already, whose status
changed or which got another delivery, is not new."""
import uuid
from datetime import datetime, timedelta

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app.config import settings

MARK = uuid.uuid4().hex[:8]
SENDER = f'new-{MARK}@example.com'
OTHER = f'other-{MARK}@example.com'


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
    from app.models import MessageCorrelation
    init_db()

    def cleanup():
        with get_db_context() as db:
            db.query(MessageCorrelation).filter(MessageCorrelation.sender.in_([SENDER, OTHER])).delete(synchronize_session=False)
            db.commit()
    cleanup()
    with get_db_context() as db:
        for minute in range(3):
            db.add(_leg(MessageCorrelation, f'<old{minute}-{MARK}@example.com>', minute=10 + minute))
        db.commit()
    from fastapi.testclient import TestClient
    from app.main import app
    yield TestClient(app)
    cleanup()


def _leg(model, message_id, minute=0, sender=SENDER, status='delivered'):
    now = datetime.utcnow().replace(microsecond=0)
    return model(correlation_key=uuid.uuid4().hex, message_id=message_id, sender=sender,
                 recipient=f'r-{uuid.uuid4().hex[:6]}@example.org', direction='outbound',
                 subject=f'{MARK}', final_status=status,
                 first_seen=now - timedelta(minutes=minute), last_seen=now, created_at=now)


def _add(*legs):
    from app.database import get_db_context
    with get_db_context() as db:
        for leg in legs:
            db.add(leg)
        db.commit()


def _watermark(client, query=''):
    response = client.get(f'/api/messages?search={MARK}{query}')
    assert response.status_code == 200, response.text
    return response.json()['watermark']


def _new(client, watermark, query=''):
    response = client.get(f'/api/messages/new?search={MARK}&after_id={watermark}{query}')
    assert response.status_code == 200, response.text
    return response.json()


def test_the_list_names_its_watermark_and_nothing_is_new_yet(client):
    mark = _watermark(client)
    assert isinstance(mark, int) and mark > 0
    answer = _new(client, mark)
    assert answer['count'] == 0
    assert answer['watermark'] >= mark


def test_messages_stored_after_the_watermark_are_new(client):
    from app.models import MessageCorrelation
    mark = _watermark(client)
    _add(_leg(MessageCorrelation, f'<a-{MARK}@example.com>'), _leg(MessageCorrelation, ''), _leg(MessageCorrelation, None))
    answer = _new(client, mark)
    assert answer['count'] == 3
    assert answer['watermark'] > mark


def test_the_deliveries_of_one_message_count_once(client):
    from app.models import MessageCorrelation
    mark = _watermark(client)
    mid = f'<multi-{MARK}@example.com>'
    _add(_leg(MessageCorrelation, mid), _leg(MessageCorrelation, mid))
    assert _new(client, mark)['count'] == 1


def test_another_delivery_of_a_message_already_there_is_not_new(client):
    from app.models import MessageCorrelation
    mark = _watermark(client)
    _add(_leg(MessageCorrelation, f'<old0-{MARK}@example.com>'))
    assert _new(client, mark)['count'] == 0


def test_a_status_change_is_not_new_mail(client):
    from app.database import get_db_context
    from app.models import MessageCorrelation
    mark = _watermark(client, '&status=bounced')
    with get_db_context() as db:
        db.query(MessageCorrelation).filter(MessageCorrelation.message_id == f'<old1-{MARK}@example.com>').update({'final_status': 'bounced'})
        db.commit()
    assert _new(client, mark, '&status=bounced')['count'] == 0


def test_the_filters_apply(client):
    from app.models import MessageCorrelation
    mark = _watermark(client)
    _add(_leg(MessageCorrelation, f'<b-{MARK}@example.com>', status='bounced'))
    assert _new(client, mark, '&status=delivered')['count'] == 0
    assert _new(client, mark, '&status=bounced')['count'] == 1
    assert _new(client, mark, f'&sender={OTHER}')['count'] == 0


def test_the_list_holds_nothing_after_its_watermark(client):
    from app.models import MessageCorrelation
    mark = _watermark(client)
    _add(_leg(MessageCorrelation, f'<late-{MARK}@example.com>'))
    # The next pages of that list: only what its first page's watermark held
    response = client.get(f'/api/messages?search={MARK}&upto_id={mark}&limit=50')
    assert response.status_code == 200, response.text
    page = response.json()
    assert page['watermark'] == mark
    assert all('late-' not in (m['message_id'] or '') for m in page['data'])
    assert _new(client, mark)['count'] == 1
    # A new list has it
    fresh = client.get(f'/api/messages?search={MARK}&limit=50').json()
    assert any('late-' in (m['message_id'] or '') for m in fresh['data'])


def test_the_watermark_is_required(client):
    assert client.get(f'/api/messages/new?search={MARK}').status_code == 422
