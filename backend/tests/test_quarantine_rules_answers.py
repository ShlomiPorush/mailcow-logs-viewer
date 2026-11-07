"""Every answer the quarantine auto-rule calls can give, so the contract check
(conftest.py, contract.py) holds each one to /openapi.json: rules saved, changed,
turned off and removed, their history, a dry run, the Read-Write key missing (403),
a database that fails (500), mailcow not answering (502) and the requests the calls
refuse (400, 404, 422). mailcow is faked; nothing leaves the test."""
import uuid
from contextlib import contextmanager
from datetime import datetime

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from fastapi.testclient import TestClient  # noqa: E402

from app import database  # noqa: E402
from app.config import settings  # noqa: E402
from app.mailcow_api import MailcowAPIError, mailcow_api  # noqa: E402
from app.main import app  # noqa: E402
from app.routers import quarantine_rules  # noqa: E402

MARK = uuid.uuid4().hex[:8]
SENDER = f'offers@{MARK}.example'
RULE = {'name': f'{MARK} offers', 'match_type': 'sender', 'match_value': SENDER, 'action': 'delete'}
BASE = '/api/quarantine/rules'


class _Broken:
    def __getattr__(self, name):
        raise RuntimeError('database gone')


@contextmanager
def _broken_context():
    yield _Broken()


def _postgres_available() -> bool:
    try:
        with database.engine.connect():
            return True
    except Exception:
        return False


@pytest.fixture
def client(monkeypatch):
    for key in ('auth_enabled', 'basic_auth_enabled', 'oauth2_enabled'):
        monkeypatch.setattr(settings._inner, key, False)
    monkeypatch.setattr(mailcow_api, 'headers_rw', {'X-API-Key': 'test-key'})
    state = {'quarantine': [{'id': 7, 'sender': SENDER, 'rcpt': 'user@example.com', 'subject': 'You won'},
                            {'id': 8, 'sender': 'friend@example.org', 'rcpt': 'user@example.com', 'subject': None}]}

    async def quarantine():
        if isinstance(state['quarantine'], Exception):
            raise state['quarantine']
        return state['quarantine']

    monkeypatch.setattr(mailcow_api, 'get_quarantine', quarantine)
    yield TestClient(app, raise_server_exceptions=False), state


@pytest.fixture
def rows(client):
    """The rules and history entries of this test, removed after it."""
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.models import QuarantineRule, QuarantineRuleLog
    database.init_db()
    with database.get_db_context() as db:
        db.add(QuarantineRuleLog(rule_id=0, rule_name=f'{MARK} gone', action='release', quarantine_id='Q1',
                                 sender=SENDER, recipient='user@example.com', subject='Invoice',
                                 matched_field='sender', matched_value=SENDER, created_at=datetime.utcnow()))
        db.commit()
    yield
    with database.get_db_context() as db:
        db.query(QuarantineRule).filter(QuarantineRule.name.like(f'{MARK}%')).delete(synchronize_session=False)
        db.query(QuarantineRuleLog).filter(QuarantineRuleLog.rule_name.like(f'{MARK}%')).delete(synchronize_session=False)
        db.commit()


def test_rules(client, rows):
    c, _ = client
    created = c.post(BASE, json=RULE)
    assert created.status_code == 200
    rule_id = created.json()['id']
    assert c.post(BASE, json={**RULE, 'name': f'{MARK} pattern', 'match_value': r'^promo-\d+@', 'is_regex': True,
                              'notes': 'Promotions'}).status_code == 200
    assert c.get(BASE).status_code == 200
    # Refused: unknown match type or action, a broken or nested-repetition pattern, a missing field
    for body in ({**RULE, 'match_type': 'header'}, {**RULE, 'action': 'bounce'},
                 {**RULE, 'is_regex': True, 'match_value': '(unclosed'},
                 {**RULE, 'is_regex': True, 'match_value': '(a+)+'}):
        assert c.post(BASE, json=body).status_code == 400
    assert c.post(BASE, json={'name': RULE['name']}).status_code == 422

    assert c.put(f'{BASE}/{rule_id}', json={'action': 'release', 'notes': 'Trusted after all'}).status_code == 200
    assert c.put(f'{BASE}/{rule_id}', json={'match_type': 'header'}).status_code == 400
    assert c.put(f'{BASE}/{rule_id}', json={'is_regex': True, 'match_value': '(a+)+'}).status_code == 400
    assert c.put(f'{BASE}/{rule_id}', json={'name': ''}).status_code == 422
    assert c.put(f'{BASE}/0', json={'enabled': False}).status_code == 404
    assert c.put(f'{BASE}/x', json={}).status_code == 422

    assert c.post(f'{BASE}/{rule_id}/toggle').json()['enabled'] is False
    assert c.post(f'{BASE}/0/toggle').status_code == 404
    assert c.post(f'{BASE}/x/toggle').status_code == 422

    assert c.get(f'{BASE}/logs?limit=200&rule_id=0').json()['total'] >= 1
    assert c.get(f'{BASE}/logs?limit=201').status_code == 422
    assert c.get(f'{BASE}/logs?offset=-1').status_code == 422
    # A negative limit is refused before it reaches the database; 0 gives the count alone
    assert c.get(f'{BASE}/logs?limit=-1').status_code == 422
    counted = c.get(f'{BASE}/logs?limit=0&rule_id=0').json()
    assert counted['total'] >= 1 and counted['data'] == []

    assert c.delete(f'{BASE}/{rule_id}').json()['success'] is True
    assert c.delete(f'{BASE}/{rule_id}').status_code == 404
    assert c.delete(f'{BASE}/x').status_code == 422


def test_dry_run(client, rows):
    c, state = client
    c.post(BASE, json=RULE)
    found = c.post(f'{BASE}/test').json()
    assert any(match['sender'] == SENDER and match['rule_enabled'] for match in found['matches'])
    state['quarantine'] = []
    assert c.post(f'{BASE}/test').json()['message'] == 'Quarantine is empty'
    state['quarantine'] = MailcowAPIError('Failed to connect to mailcow API')
    assert c.post(f'{BASE}/test').status_code == 502


def test_rules_need_the_read_write_key(client, monkeypatch):
    c, _ = client
    monkeypatch.setattr(mailcow_api, 'headers_rw', None)
    assert c.get(BASE).status_code == 403
    assert c.post(BASE, json=RULE).status_code == 403
    assert c.get(f'{BASE}/logs').status_code == 403
    assert c.post(f'{BASE}/test').status_code == 403
    assert c.put(f'{BASE}/1', json={}).status_code == 403
    assert c.delete(f'{BASE}/1').status_code == 403
    assert c.post(f'{BASE}/1/toggle').status_code == 403


def test_rules_when_the_database_fails(client, monkeypatch):
    c, _ = client
    monkeypatch.setattr(quarantine_rules, 'get_db_context', _broken_context)
    assert c.get(BASE).status_code == 500
    assert c.post(BASE, json=RULE).status_code == 500
    assert c.get(f'{BASE}/logs').status_code == 500
    assert c.post(f'{BASE}/test').status_code == 500
    assert c.put(f'{BASE}/1', json={}).status_code == 500
    assert c.delete(f'{BASE}/1').status_code == 500
    assert c.post(f'{BASE}/1/toggle').status_code == 500
