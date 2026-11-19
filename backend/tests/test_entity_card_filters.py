"""The filters the entity card's "Show messages" and "Show security events" open
the Messages and Security pages with, so the page lists what the card counted:

- Messages address=: from or to the address, whole, in any case;
  domain=: from or to an address on the domain (the part after the last @,
  so a subdomain is not included). In the list, the facet counts, the
  new-mail count and the CSV export alike.
- Security events exact_username=true: the user name as a whole address;
  username_domain=: user names on the domain. In the list and its CSV export.

Without them the filters match a part, as they always have."""
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
DOMAIN = f"x{MARK}.example"
SUB = f"sub.{DOMAIN}"
ANN, JOANN = f"ann@{DOMAIN}", f"joann@{DOMAIN}"
OUTSIDE = f"ann@y{MARK}.example"
AT = datetime(2020, 4, 10, 12, 0, 0)
RANGE = {"start_date": "2020-04-01", "end_date": "2020-04-20"}

# name: (sender, recipient)
MESSAGES = {
    "from-ann": (ANN.upper(), OUTSIDE),
    "to-ann": (OUTSIDE, ANN),
    "joann": (JOANN, OUTSIDE),
    "sub": (f"bob@{SUB}", OUTSIDE),
    "outside": (OUTSIDE, f"carol@y{MARK}.example"),
}
# name: user name a client tried
EVENTS = {"ev-ann": ANN.upper(), "ev-joann": JOANN, "ev-sub": f"bob@{SUB}", "ev-outside": OUTSIDE}


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _cleanup():
    from app.database import get_db_context
    from app.models import MessageCorrelation, NetfilterLog
    with get_db_context() as db:
        db.query(MessageCorrelation).filter(MessageCorrelation.correlation_key.like(f"{MARK}-%")).delete(synchronize_session=False)
        db.query(NetfilterLog).filter(NetfilterLog.message.like(f"%{MARK}%")).delete(synchronize_session=False)
        db.commit()


@pytest.fixture()
def client(monkeypatch):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    for key in ('auth_enabled', 'basic_auth_enabled', 'oauth2_enabled'):
        monkeypatch.setattr(settings._inner, key, False)
    monkeypatch.setattr(settings._inner, 'blacklist_emails', '')
    from app.database import init_db, get_db_context
    from app.models import MessageCorrelation, NetfilterLog
    init_db()
    _cleanup()
    with get_db_context() as db:
        for i, (name, (sender, recipient)) in enumerate(MESSAGES.items()):
            db.add(MessageCorrelation(correlation_key=f"{MARK}-{name}", message_id=f"<{name}.{MARK}@example.com>",
                                      sender=sender, recipient=recipient, subject=f"{name} {MARK}",
                                      direction="outbound", final_status="delivered",
                                      first_seen=AT + timedelta(minutes=i), last_seen=AT + timedelta(minutes=i),
                                      created_at=AT))
        for i, (name, username) in enumerate(EVENTS.items()):
            db.add(NetfilterLog(time=AT + timedelta(minutes=i), priority="warn", ip=f"192.0.2.{i + 1}", username=username,
                                rule_id=3, action="warning", message=f"{name} {MARK}"))
        db.commit()
    from fastapi.testclient import TestClient
    from app.main import app
    yield TestClient(app)
    _cleanup()


def _names(rows):
    return sorted(r.split()[0] for r in rows if MARK in (r or ""))


MESSAGE_CASES = [
    ({"address": ANN}, ["from-ann", "to-ann"]),
    ({"address": ANN.upper()}, ["from-ann", "to-ann"]),
    ({"domain": DOMAIN}, ["from-ann", "joann", "to-ann"]),
    ({"domain": DOMAIN.upper() + "."}, ["from-ann", "joann", "to-ann"]),
    ({"domain": SUB}, ["sub"]),
    ({"domain": "not a domain"}, []),
]


@pytest.mark.parametrize("filters,expected", MESSAGE_CASES)
def test_messages_list(client, filters, expected):
    res = client.get("/api/messages", params={**RANGE, **filters})
    assert res.status_code == 200, res.text
    assert _names(m["subject"] for m in res.json()["data"]) == expected


@pytest.mark.parametrize("filters,expected", MESSAGE_CASES)
def test_messages_facets_and_new_count(client, filters, expected):
    facets = client.get("/api/messages/facets", params={**RANGE, **filters}).json()
    assert facets["status"]["delivered"] == len(expected)
    assert facets["direction"]["outbound"] == len(expected)
    new = client.get("/api/messages/new", params={"after_id": 0, **RANGE, **filters}).json()
    assert new["count"] == len(expected)


@pytest.mark.parametrize("filters,expected", MESSAGE_CASES)
def test_messages_export(client, filters, expected):
    res = client.get("/api/export/messages/csv", params={**RANGE, **filters})
    if not expected:
        assert res.status_code == 404
        return
    assert res.status_code == 200, res.text
    rows = csv.DictReader(io.StringIO(res.content.decode("utf-8-sig")))
    assert _names(r["Subject"] for r in rows) == expected


def test_messages_address_holds_with_the_other_filters(client):
    """address narrows like any filter: with a sender it is both."""
    res = client.get("/api/messages", params={**RANGE, "address": ANN, "sender": OUTSIDE, "exact": "true"}).json()
    assert _names(m["subject"] for m in res["data"]) == ["to-ann"]


EVENT_CASES = [
    ({"username": ANN, "exact_username": "true"}, ["ev-ann"]),
    ({"username": ANN}, ["ev-ann", "ev-joann"]),                 # a part, as before
    ({"username_domain": DOMAIN}, ["ev-ann", "ev-joann"]),
    ({"username_domain": SUB}, ["ev-sub"]),
    ({"username_domain": "not a domain"}, []),
]


@pytest.mark.parametrize("filters,expected", EVENT_CASES)
def test_security_events_list_and_export(client, filters, expected):
    params = {**RANGE, **filters}
    res = client.get("/api/logs/netfilter", params={**params, "limit": 500})
    assert res.status_code == 200, res.text
    assert _names(row["message"] for row in res.json()["data"]) == expected
    exported = client.get("/api/export/netfilter/csv", params=params)
    if not expected:
        assert exported.status_code == 404
        return
    assert exported.status_code == 200, exported.text
    assert sorted(name for name in EVENTS if f"{name} {MARK}" in exported.text) == expected
