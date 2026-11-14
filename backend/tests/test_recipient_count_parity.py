"""The Messages list and the message dialog count recipients the same way.

The dialog counts in the browser (messageRecipients() in
frontend/message-details.js); the list shows the server's count
(app/services/message_recipients.py). The shared cases in
fixtures/recipient_count_cases.json run through the dialog's count in
.github/tests/recipient-count-parity.test.cjs and through the server's here:
the helper on its own, then the real list and details answers.
"""
import hashlib
import json
import pathlib
import uuid
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

FIXTURE = json.loads((pathlib.Path(__file__).parent / 'fixtures' / 'recipient_count_cases.json').read_text(encoding='utf-8'))
CASES = FIXTURE['cases']
MARKER = 'parity.example.test'
SENDER = f'sender@{MARKER}'


def _line(queue_id, entry):
    orig = f"orig_to=<{entry['orig_to']}>, " if entry.get('orig_to') else ''
    return FIXTURE['line'].replace('{queue}', queue_id).replace('{to}', entry['to']).replace('{orig}', orig)


def _exclude(monkeypatch, case):
    from app.config import settings
    monkeypatch.setattr(settings._inner, 'blacklist_emails', ','.join(case.get('excluded', [])))


def test_the_shared_cases_are_there():
    assert len(CASES) >= 13
    assert len([case for case in CASES if case.get('other_legs')]) >= 4
    assert all(MARKER in address for case in CASES for address in case['recipients'])


def _shown(case, leg):
    """The server leaves out a delivery to or from an excluded address: its own
    recipient, or an address a line of its queue names (such as orig_to)."""
    excluded = [address.lower() for address in case.get('excluded', [])]
    named = [leg['recipient']] + [a for entry in leg['postfix'] for a in (entry['to'], entry.get('orig_to')) if a]
    return not any(address.lower() in excluded for address in named)


@pytest.mark.parametrize('case', CASES, ids=[c['name'] for c in CASES])
def test_the_server_counts_as_the_dialog(case, monkeypatch):
    from app.services.message_recipients import (listed_recipients, resolve_recipients, union_recipients,
                                                 written_address)
    _exclude(monkeypatch, case)

    def resolve(leg):
        rspamd = SimpleNamespace(recipients_smtp=leg['rspamd']) if leg['rspamd'] is not None else None
        lines = [(entry['to'], written_address(entry['to'], _line('4F2A1B3C9D', entry))) for entry in leg['postfix']]
        listed = listed_recipients(rspamd, (to for to, _ in lines))
        assert sorted(listed) == sorted(leg['recipients'])
        return resolve_recipients(listed, lines, leg['recipient'])
    others = [leg for leg in case.get('other_legs', []) if _shown(case, leg)]
    for leg in others:
        assert sorted(resolve(leg)) == sorted(leg['resolved'])
    assert len(union_recipients([resolve(case)] + [resolve(leg) for leg in others])) == case['expected']


# ---------- the real answers ----------

def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _cleanup():
    from app.database import get_db_context
    from app.models import MessageCorrelation, PostfixLog, RspamdLog
    with get_db_context() as db:
        db.query(PostfixLog).filter(PostfixLog.message.like(f'%{MARKER}%')).delete(synchronize_session=False)
        db.query(RspamdLog).filter(RspamdLog.message_id.like(f'%{MARKER}%')).delete(synchronize_session=False)
        db.query(MessageCorrelation).filter(
            MessageCorrelation.message_id.like(f'%{MARKER}%')).delete(synchronize_session=False)
        db.commit()


@pytest.fixture()
def client(monkeypatch):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from fastapi.testclient import TestClient
    from app.config import settings
    from app.database import init_db
    from app.main import app
    import app.models as _tables  # noqa: F401 - the tables init_db creates on an empty database
    init_db()
    monkeypatch.setattr(settings._inner, 'blacklist_emails', '')
    _cleanup()
    yield TestClient(app)
    _cleanup()


def _seed_leg(db, msgid, leg, t0):
    from app.models import MessageCorrelation, PostfixLog, RspamdLog
    queue_id = uuid.uuid4().hex[:10].upper()
    rspamd_id = None
    if leg['rspamd'] is not None:
        row = RspamdLog(time=t0, message_id=msgid, sender_smtp=SENDER, recipients_smtp=leg['rspamd'], score=0.5,
                        required_score=15.0, action='no action', is_spam=False, direction='inbound', user='unknown')
        db.add(row)
        db.flush()
        rspamd_id = row.id
    for entry in leg['postfix']:
        db.add(PostfixLog(time=t0 + timedelta(seconds=entry['at']), program='postfix/lmtp', priority='info',
                          message=_line(queue_id, entry), queue_id=queue_id, recipient=entry['to'],
                          status='sent', relay='dovecot'))
    key = hashlib.sha256(f'{msgid}:{queue_id}'.encode()).hexdigest()
    db.add(MessageCorrelation(correlation_key=key, message_id=msgid, queue_id=queue_id, rspamd_log_id=rspamd_id,
                              sender=SENDER, recipient=leg['recipient'], subject='Parity', direction='inbound',
                              final_status='delivered', is_complete=True, first_seen=t0, last_seen=t0))
    return key


@pytest.mark.parametrize('case', CASES, ids=[c['name'] for c in CASES])
def test_the_list_and_the_details_give_the_shared_count(case, client, monkeypatch):
    from app.database import get_db_context
    msgid = f'{uuid.uuid4().hex}@{MARKER}'
    t0 = datetime.utcnow() - timedelta(minutes=10)
    with get_db_context() as db:
        key = _seed_leg(db, msgid, case, t0)
        for n, leg in enumerate(case.get('other_legs', []), start=1):
            _seed_leg(db, msgid, leg, t0 + timedelta(seconds=30 * n))
        db.commit()
    # An address is excluded after the mail was stored
    _exclude(monkeypatch, case)

    rows = {row['correlation_key']: row for row in
            client.get('/api/messages', params={'search': MARKER, 'limit': 50}).json()['data']}
    details = client.get(f'/api/message/{key}/details').json()
    # Lines of the same second come in either order: the list is compared as a set
    assert sorted(details['recipients']) == sorted(case['recipients'])
    # Each other delivery with its own recipients; one to an excluded address is left out
    others = [leg for leg in case.get('other_legs', []) if _shown(case, leg)]
    assert (sorted(sorted(d['recipients']) for d in details['related_deliveries'])
            == sorted(sorted(leg['resolved']) for leg in others))
    assert details['recipient_count'] == case['expected']
    assert rows[key]['recipient_count'] == case['expected']
    # The row's deliveries are the ones the details list: this one and the others shown
    assert rows[key]['deliveries'] == 1 + len(others)
