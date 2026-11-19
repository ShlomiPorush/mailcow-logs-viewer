"""exact=true on the Messages calls: sender, recipient, user and ip match whole
values (the entity card's "Show messages"), in the list, the new-mail count,
the facet counts and the CSV export alike. Without it they still match a part,
as they always have."""
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
ANN, JOANN = f"ann@{DOMAIN}", f"joann@{DOMAIN}"
IP, SIMILAR_IP = "192.0.2.4", "192.0.2.45"
AT = datetime(2020, 4, 10, 12, 0, 0)
RANGE = {"start_date": "2020-04-01", "end_date": "2020-04-20"}


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _cleanup():
    from app.database import get_db_context
    from app.models import MessageCorrelation, RspamdLog
    with get_db_context() as db:
        db.query(MessageCorrelation).filter(MessageCorrelation.correlation_key.like(f"{MARK}-%")).delete(synchronize_session=False)
        db.query(RspamdLog).filter(RspamdLog.correlation_key.like(f"{MARK}-%")).delete(synchronize_session=False)
        db.commit()


@pytest.fixture()
def client(monkeypatch):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    for key in ('auth_enabled', 'basic_auth_enabled', 'oauth2_enabled'):
        monkeypatch.setattr(settings._inner, key, False)
    monkeypatch.setattr(settings._inner, 'blacklist_emails', '')
    from app.database import init_db, get_db_context
    from app.models import MessageCorrelation, RspamdLog
    init_db()
    _cleanup()
    with get_db_context() as db:
        for i, (name, sender, recipient, ip, user) in enumerate((
            ("ann", ANN.upper(), f"to@{DOMAIN}", IP, ANN),
            ("joann", JOANN, f"to@{DOMAIN}", SIMILAR_IP, JOANN),
            ("to-ann", f"from@{DOMAIN}", ANN, IP, None),
            ("to-joann", f"from@{DOMAIN}", JOANN, SIMILAR_IP, None),
        )):
            scan = RspamdLog(time=AT + timedelta(minutes=i), ip=ip, user=user, correlation_key=f"{MARK}-{name}")
            db.add(scan)
            db.flush()
            db.add(MessageCorrelation(correlation_key=f"{MARK}-{name}", message_id=f"<{name}.{MARK}@example.com>",
                                      sender=sender, recipient=recipient, subject=f"{name} {MARK}",
                                      direction="outbound", final_status="delivered",
                                      first_seen=AT + timedelta(minutes=i), last_seen=AT + timedelta(minutes=i),
                                      created_at=AT, rspamd_log_id=scan.id))
        db.commit()
    from fastapi.testclient import TestClient
    from app.main import app
    yield TestClient(app)
    _cleanup()


CASES = [
    ({"sender": ANN}, ["ann"], ["ann", "joann"]),
    ({"recipient": ANN}, ["to-ann"], ["to-ann", "to-joann"]),
    ({"user": ANN}, ["ann"], ["ann", "joann"]),
    ({"ip": IP}, ["ann", "to-ann"], ["ann", "joann", "to-ann", "to-joann"]),
    ({"ip": "192.0.2.04"}, [], []),     # not an address: matched as written, so nothing
]


def _subjects(rows):
    return sorted(r.split()[0] for r in rows)


@pytest.mark.parametrize("filters,exact,partial", CASES)
def test_list(client, filters, exact, partial):
    def subjects(**extra):
        res = client.get("/api/messages", params={**RANGE, **filters, **extra})
        assert res.status_code == 200, res.text
        return _subjects(m["subject"] for m in res.json()["data"] if MARK in (m["subject"] or ""))
    assert subjects(exact="true") == exact
    assert subjects() == partial
    assert subjects(exact="false") == partial


@pytest.mark.parametrize("filters,exact,partial", CASES)
def test_facets(client, filters, exact, partial):
    def counts(**extra):
        res = client.get("/api/messages/facets", params={**RANGE, **filters, **extra})
        assert res.status_code == 200, res.text
        return res.json()
    assert counts(exact="true")["status"]["delivered"] == len(exact)
    assert counts(exact="true")["direction"]["outbound"] == len(exact)
    assert counts()["status"]["delivered"] == len(partial)


@pytest.mark.parametrize("filters,exact,partial", CASES)
def test_new_messages(client, filters, exact, partial):
    def count(**extra):
        res = client.get("/api/messages/new", params={"after_id": 0, **RANGE, **filters, **extra})
        assert res.status_code == 200, res.text
        return res.json()["count"]
    assert count(exact="true") == len(exact)
    assert count() == len(partial)


@pytest.mark.parametrize("filters,exact,partial", CASES)
def test_export(client, filters, exact, partial):
    def subjects(**extra):
        res = client.get("/api/export/messages/csv", params={**RANGE, **filters, **extra})
        if res.status_code == 404:          # nothing to export
            return []
        assert res.status_code == 200, res.text
        rows = csv.DictReader(io.StringIO(res.content.decode("utf-8-sig")))
        return _subjects(r["Subject"] for r in rows if MARK in r["Subject"])
    assert subjects(exact="true") == exact
    assert subjects() == partial


def test_export_keeps_the_rspamd_columns_with_an_ip_filter(client):
    """The filter joins Rspamd itself; the export's own columns still come with each row."""
    res = client.get("/api/export/messages/csv", params={**RANGE, "ip": IP, "exact": "true"})
    rows = [r for r in csv.DictReader(io.StringIO(res.content.decode("utf-8-sig"))) if MARK in r["Subject"]]
    assert sorted((r["Subject"].split()[0], r["IP"], r["User"]) for r in rows) == [
        ("ann", IP, ANN), ("to-ann", IP, "")]


def test_exact_matches_an_address_in_any_case(client):
    res = client.get("/api/messages", params={**RANGE, "sender": ANN.upper(), "exact": "true"}).json()
    assert _subjects(m["subject"] for m in res["data"] if MARK in m["subject"]) == ["ann"]
