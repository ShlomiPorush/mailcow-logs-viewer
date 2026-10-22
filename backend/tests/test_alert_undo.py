"""Undo for dismissing security alerts: every dismissal answers with a receipt
of exactly what it changed, Dismiss all changes only the alerts the list had,
and Undo by receipt re-opens those and nothing a later dismissal changed."""
import importlib.util
import pathlib
import uuid
from datetime import datetime

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

MARK = uuid.uuid4().hex[:8]
SUBJECT = f'undo-{MARK}@alerts.example'


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
    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app)


def _add(n=1, subject=SUBJECT):
    from app.database import get_db_context
    from app.models import SecurityAlert
    with get_db_context() as db:
        rows = [SecurityAlert(alert_type='volume_spike', severity='warning', subject=subject, title=f'Spike {i}', created_at=datetime.utcnow())
                for i in range(n)]
        db.add_all(rows)
        db.commit()
        return [r.id for r in rows]


def _open(ids):
    from app.database import get_db_context
    from app.models import SecurityAlert
    with get_db_context() as db:
        return sorted(r.id for r in db.query(SecurityAlert).filter(SecurityAlert.id.in_(ids), SecurityAlert.acknowledged == False))  # noqa: E712


def test_a_dismissal_has_a_receipt_and_undo_reopens_it_once(db_ready):
    c = _client()
    [alert] = _add()
    first = c.post(f'/api/security-alerts/{alert}/acknowledge').json()
    assert first['acknowledged'] == 1 and first['ids'] == [alert] and first['receipt']
    # Another tab dismisses it too: nothing changed there, so no receipt to undo
    again = c.post(f'/api/security-alerts/{alert}/acknowledge').json()
    assert again['acknowledged'] == 0 and again['receipt'] is None
    undone = c.post(f"/api/security-alerts/acknowledgements/{first['receipt']}/undo").json()
    assert undone['restored'] == 1 and undone['ids'] == [alert] and _open([alert]) == [alert]
    assert c.post(f"/api/security-alerts/acknowledgements/{first['receipt']}/undo").json()['restored'] == 0


def test_an_old_undo_does_not_reopen_a_later_dismissal(db_ready):
    c = _client()
    [alert] = _add()
    r1 = c.post(f'/api/security-alerts/{alert}/acknowledge').json()['receipt']
    c.post(f'/api/security-alerts/acknowledgements/{r1}/undo')
    r2 = c.post(f'/api/security-alerts/{alert}/acknowledge').json()['receipt']
    assert r2 and r2 != r1
    assert c.post(f'/api/security-alerts/acknowledgements/{r1}/undo').json()['restored'] == 0
    assert _open([alert]) == []


def test_dismiss_all_changes_only_the_alerts_the_list_had_even_one_committed_later_with_a_lower_id(db_ready):
    from sqlalchemy.orm import Session
    from app.database import engine
    from app.models import SecurityAlert
    c = _client()
    shown = _add(3)
    # Transaction A takes an id and waits; B takes a higher one and commits first
    a = Session(engine)
    late = SecurityAlert(alert_type='volume_spike', subject=f'late-{MARK}@alerts.example', title='Late', created_at=datetime.utcnow())
    a.add(late)
    a.flush()
    [early] = _add(1, subject=f'early-{MARK}@alerts.example')
    assert late.id < early
    listed = c.get('/api/security-alerts', params={'acknowledged': 'false', 'limit': 20}).json()
    ids = [i for i in listed['unacknowledged_ids'] if i in shown + [early, late.id]]
    assert set(ids) == set(shown + [early]) and len(listed['unacknowledged_ids']) == listed['unacknowledged_count']
    a.commit()
    late_id = late.id
    a.close()
    done = c.post('/api/security-alerts/acknowledge-all', json={'ids': ids}).json()
    assert done['acknowledged'] == 4 and done['receipt']
    assert _open(shown + [early, late_id]) == [late_id], 'the alert the list did not have stays open'
    undone = c.post(f"/api/security-alerts/acknowledgements/{done['receipt']}/undo").json()
    assert undone['restored'] == 4 and sorted(undone['ids']) == sorted(shown + [early])


def test_one_undo_reopens_a_large_dismiss_all(db_ready):
    c = _client()
    ids = _add(1500)
    done = c.post('/api/security-alerts/acknowledge-all', json={'ids': ids}).json()
    assert done['acknowledged'] == 1500
    assert c.post(f"/api/security-alerts/acknowledgements/{done['receipt']}/undo").json()['restored'] == 1500
    assert len(_open(ids)) == 1500


def test_dismiss_all_without_ids_keeps_its_old_meaning_and_can_be_undone(db_ready):
    c = _client()
    ids = _add(2)
    done = c.post('/api/security-alerts/acknowledge-all').json()
    assert done['acknowledged'] >= 2 and set(ids) <= set(done['ids'])
    c.post(f"/api/security-alerts/acknowledgements/{done['receipt']}/undo")
    assert _open(ids) == sorted(ids)


def test_bad_requests_are_refused(db_ready):
    c = _client()
    assert c.post('/api/security-alerts/999999999/acknowledge').status_code == 404
    assert c.post('/api/security-alerts/acknowledgements/not-a-receipt/undo').status_code == 422
    assert c.post('/api/security-alerts/acknowledge-all', json={'ids': []}).status_code == 422
    assert c.post('/api/security-alerts/acknowledge-all', json={'ids': list(range(10001))}).status_code == 422
    assert c.post('/api/security-alerts/acknowledge-all', json={'ids': ['x']}).status_code == 422
    # An unknown receipt changes nothing
    assert c.post(f'/api/security-alerts/acknowledgements/{uuid.uuid4()}/undo').json()['restored'] == 0


def test_the_migration_adds_the_receipt_on_an_existing_install_and_runs_again_safely(db_ready):
    from sqlalchemy import create_engine, inspect, text
    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    from app.database import engine
    from app.models import Base, SecurityAlert
    path = sorted((pathlib.Path(__file__).resolve().parent.parent / 'alembic' / 'versions').glob('0020_*.py'))[0]
    spec = importlib.util.spec_from_file_location('rev0020', path)
    revision = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(revision)
    schema = 'alert_undo_' + MARK
    with engine.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA {schema}'))
    isolated = create_engine(engine.url, connect_args={'options': f'-csearch_path={schema}'})

    def run(step):
        with isolated.begin() as conn:
            with Operations.context(MigrationContext.configure(conn)):
                step()
    try:
        # As 0019 left it: the table without the receipt, with an alert in it
        Base.metadata.create_all(isolated, tables=[SecurityAlert.__table__])
        with isolated.begin() as conn:
            conn.execute(text('DROP INDEX IF EXISTS ix_security_alerts_ack_batch'))
            conn.execute(text('ALTER TABLE security_alerts DROP COLUMN ack_batch'))
            conn.execute(text("INSERT INTO security_alerts (alert_type, title, acknowledged) VALUES ('volume_spike', 'kept', true)"))
        run(revision.upgrade)
        run(revision.upgrade)   # a restart, or a fresh install whose table already has it
        columns = {c['name'] for c in inspect(isolated).get_columns('security_alerts')}
        assert 'ack_batch' in columns
        with isolated.connect() as conn:
            assert conn.execute(text('SELECT title, acknowledged, ack_batch FROM security_alerts')).all() == [('kept', True, None)]
        run(revision.downgrade)
        assert 'ack_batch' not in {c['name'] for c in inspect(isolated).get_columns('security_alerts')}
        run(revision.upgrade)
        assert 'ix_security_alerts_ack_batch' in {i['name'] for i in inspect(isolated).get_indexes('security_alerts')}
    finally:
        isolated.dispose()
        with engine.begin() as conn:
            conn.execute(text(f'DROP SCHEMA {schema} CASCADE'))
