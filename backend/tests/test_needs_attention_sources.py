"""What Needs attention (the Dashboard panel and the header bell) reads besides
the rows: the open critical alerts past the rows asked for, and whether the
container counts were read at all."""
import uuid
from datetime import datetime, timedelta
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

MARK = uuid.uuid4().hex[:8]
SUBJECT = f'attention-{MARK}@alerts.example'


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


@pytest.fixture()
def db_ready():
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import init_db, get_db_context
    from app.models import SecurityAlert
    init_db()

    def cleanup():
        with get_db_context() as db:
            db.query(SecurityAlert).filter(SecurityAlert.subject.like(f'%{MARK}%')).delete(synchronize_session=False)
            db.commit()
    cleanup()
    yield
    cleanup()


def _client():
    from app.main import app
    return TestClient(app)


def _add(severity, n, age_minutes):
    from app.database import get_db_context
    from app.models import SecurityAlert
    at = datetime.utcnow() - timedelta(minutes=age_minutes)
    with get_db_context() as db:
        rows = [SecurityAlert(alert_type='volume_spike', severity=severity, subject=SUBJECT, title=f'{severity} {i}', created_at=at)
                for i in range(n)]
        db.add_all(rows)
        db.commit()
        return [r.id for r in rows]


def test_open_critical_alerts_are_counted_past_the_rows_asked_for(db_ready):
    c = _client()
    before = c.get('/api/security-alerts?acknowledged=false&limit=20').json()['unacknowledged_critical']
    # One critical alert older than 25 newer warnings: not among the 20 rows
    [critical] = _add('critical', 1, age_minutes=60)
    _add('warning', 25, age_minutes=1)
    answer = c.get('/api/security-alerts?acknowledged=false&limit=20').json()
    assert len(answer['alerts']) == 20
    assert critical not in [a['id'] for a in answer['alerts']]
    assert answer['unacknowledged_critical'] == before + 1
    # Dismissed, it is no longer counted
    c.post(f'/api/security-alerts/{critical}/acknowledge')
    assert c.get('/api/security-alerts?acknowledged=false&limit=20').json()['unacknowledged_critical'] == before


def _summary(monkeypatch, containers):
    from app.routers import status
    import app.services.figures as figures
    monkeypatch.setattr(status, '_get_containers_status_internal', containers)
    monkeypatch.setattr(figures, 'storage_figure', AsyncMock(return_value={'used_percent': '1%', 'valid': True}))
    monkeypatch.setattr(status, 'get_mailcow_info', AsyncMock(return_value={}))
    app = FastAPI()
    app.include_router(status.router)
    with TestClient(app) as client:
        return client.get('/status/summary').json()


def test_container_counts_say_whether_mailcow_answered(monkeypatch):
    read = _summary(monkeypatch, AsyncMock(return_value={'summary': {'running': 17, 'stopped': 1, 'total': 18}}))
    assert read['containers'] == {'running': 17, 'stopped': 1, 'total': 18}
    assert read['containers_known'] is True
    # No answer: zeros, which must not read as "nothing is stopped"
    failed = _summary(monkeypatch, AsyncMock(side_effect=RuntimeError('mailcow did not answer')))
    assert failed['containers'] == {'running': 0, 'stopped': 0, 'total': 0}
    assert failed['containers_known'] is False
    # An answer with no containers at all is not a reading either
    empty = _summary(monkeypatch, AsyncMock(return_value={'summary': {'running': 0, 'stopped': 0, 'total': 0}}))
    assert empty['containers_known'] is False
