"""What the entity card's actions rely on, from the review of the card actions:

- One blocklist check at a time, whoever starts it: the scheduled and manual
  job and POST /api/blacklist/check (with or without a host) share one lock,
  and the POST answers status busy, starting nothing, while a check runs.
- An alias offers Open mailbox only when it delivers to a mailbox here: the
  card's mailbox source names that mailbox (alias.local_mailbox), never an
  outside first target.
- GET /api/mailbox-stats/all?username= finds one mailbox by its whole
  address (either form of an IDN domain), wherever the pages would put it.
"""
import uuid

import idna

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app.config import settings

MARK = uuid.uuid4().hex[:8]
DOMAIN = f"r{MARK}.example"
IDN_UNICODE = f"bücher{MARK}.example"
IDN_ASCII = idna.encode(IDN_UNICODE).decode()   # as mailcow stores it: xn--...
OWNER = f"zz.owner@{DOMAIN}"   # sorts after user00..user59
TO_LOCAL = f"team@{DOMAIN}"
TO_OUTSIDE = f"fwd@{DOMAIN}"


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


@pytest.fixture()
def client(monkeypatch):
    for key in ('auth_enabled', 'basic_auth_enabled', 'oauth2_enabled'):
        monkeypatch.setattr(settings._inner, key, False)
    monkeypatch.setattr(settings._inner, 'disabled_features', '')
    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app)


# ---------------------------------------------------------------- one blocklist check at a time

def test_the_job_and_a_single_address_share_one_lock():
    from app import scheduler
    assert scheduler.blacklist_check_lock() is scheduler._blacklist_check_lock


class _Busy:
    def locked(self):
        return True


@pytest.mark.parametrize("params", [{"host": "203.0.113.45", "force": "true"}, {"force": "true"}, {}])
def test_post_answers_busy_and_starts_nothing_while_a_check_runs(client, monkeypatch, params):
    from app import scheduler
    from app.routers import blacklist
    started = []

    async def fake_results(**kwargs):
        started.append(('host', kwargs))
        return {"status": "clean"}

    async def fake_job(**kwargs):
        started.append(('job', kwargs))

    monkeypatch.setattr(scheduler, 'blacklist_check_lock', lambda: _Busy())
    monkeypatch.setattr(scheduler, 'check_monitored_hosts_job', fake_job)
    monkeypatch.setattr(blacklist, 'get_blacklist_check_results', fake_results)
    res = client.post("/api/blacklist/check", params=params)
    assert res.status_code == 200, res.text
    assert res.json() == {"status": "busy", "message": "A blocklist check is already running. Try again when it is done."}
    assert started == []


def test_a_single_address_is_checked_holding_the_lock(client, monkeypatch):
    from app import scheduler
    from app.routers import blacklist
    held = []

    async def fake_results(force, ip):
        held.append((ip, force, scheduler.blacklist_check_lock().locked()))
        return {"server_ip": ip, "checked_at": "2026-10-28T12:00:00Z", "total_blacklists": 42, "listed_count": 0,
                "clean_count": 42, "error_count": 0, "timeout_count": 0, "status": "clean", "results": []}

    monkeypatch.setattr(blacklist, 'get_blacklist_check_results', fake_results)
    res = client.post("/api/blacklist/check", params={"host": "203.0.113.45", "force": "true"})
    assert res.status_code == 200 and res.json()["status"] == "clean"
    assert held == [("203.0.113.45", True, True)]
    assert not scheduler.blacklist_check_lock().locked(), "released after the check"


def test_busy_is_documented():
    from app.main import app
    schema = app.openapi()
    body = schema["paths"]["/api/blacklist/check"]["post"]["responses"]["200"]
    assert "CheckBusy" in str(body)
    assert "CheckBusy" in schema["components"]["schemas"]


# ---------------------------------------------------------------- alias and Mailbox Stats

@pytest.fixture()
def boxes(client):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import init_db, get_db_context
    from app.models import AliasStatistics, MailboxStatistics
    from app.routers.mailbox_stats import clear_stats_cache
    init_db()

    def cleanup():
        with get_db_context() as db:
            db.query(AliasStatistics).filter(AliasStatistics.domain == DOMAIN).delete(synchronize_session=False)
            db.query(MailboxStatistics).filter(MailboxStatistics.domain.in_([DOMAIN, IDN_ASCII])).delete(synchronize_session=False)
            db.commit()
    cleanup()
    with get_db_context() as db:
        # 60 mailboxes: the one asked for sorts last, past the first page of 50
        for i in range(60):
            db.add(MailboxStatistics(username=f"user{i:02d}@{DOMAIN}", domain=DOMAIN, name=f"User {i}", active=True))
        db.add(MailboxStatistics(username=OWNER, domain=DOMAIN, name="Zz Owner", active=False))
        db.add(MailboxStatistics(username=f"ann@{IDN_ASCII}", domain=IDN_ASCII, name="Ann", active=True))
        db.add(AliasStatistics(alias_address=TO_LOCAL, goto=f"{OWNER.upper()},partner@outside.test", domain=DOMAIN,
                               active=True, primary_mailbox=OWNER.upper()))
        db.add(AliasStatistics(alias_address=TO_OUTSIDE, goto="ann@outside.test", domain=DOMAIN,
                               active=True, primary_mailbox="ann@outside.test"))
        db.commit()
    clear_stats_cache()
    yield client
    cleanup()
    clear_stats_cache()


def _mailbox_source(client, address):
    res = client.get("/api/entities/address", params={"value": address})
    assert res.status_code == 200, res.text
    source = res.json()["sources"]["mailbox"]
    assert source["state"] == "ok", source
    return source


def test_an_alias_names_its_mailbox_only_when_it_is_one_here(boxes):
    local = _mailbox_source(boxes, TO_LOCAL)
    assert local["local"] is False
    assert local["alias"]["local_mailbox"] == OWNER, "the mailbox as stored"
    outside = _mailbox_source(boxes, TO_OUTSIDE)
    assert outside["alias"]["primary_mailbox"] == "ann@outside.test"
    assert outside["alias"]["local_mailbox"] is None
    # A mailbox's own card has no alias part
    assert _mailbox_source(boxes, OWNER)["alias"] is None


def _all(client, **params):
    res = client.get("/api/mailbox-stats/all", params={"active_only": "false", "sort_by": "username", "sort_order": "asc",
                                                      "page_size": 50, "date_range": "7days", **params})
    assert res.status_code == 200, res.text
    return [m["username"] for m in res.json()["mailboxes"]]


def test_mailbox_stats_finds_one_mailbox_by_its_whole_address(boxes):
    # Past the first page of a search, it is not there
    assert OWNER not in _all(boxes, search=DOMAIN)
    assert _all(boxes, username=OWNER) == [OWNER]
    assert _all(boxes, username=OWNER.upper()) == [OWNER], "in any case"
    assert _all(boxes, username=f"user1@{DOMAIN}") == [], "whole, not a part of user10"
    # An IDN domain, written either way
    assert _all(boxes, username=f"ann@{IDN_UNICODE}") == [f"ann@{IDN_ASCII}"]
    assert _all(boxes, username=f"ann@{IDN_ASCII}") == [f"ann@{IDN_ASCII}"]
