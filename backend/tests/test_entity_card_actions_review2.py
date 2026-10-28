"""Second review of the entity card actions:

- Messages exact_ip: the IP matched whole while every other filter still
  matches a part (a sender added to an IP card's list), in the list, the facet
  counts, the new-mail count and the CSV export. The generic exact still works.
- A manual Run of the blocklist job while a single address check holds the
  check's lock is refused before the job is marked running; a run that skips
  because such a check took the lock meanwhile leaves the status as it was.
- The scheduled scan waits for a single address check (bounded) instead of
  losing the day's scan; it skips only for another full scan.
"""
import asyncio
import csv
import io
import uuid
from datetime import datetime, timedelta

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app import scheduler
from app.config import settings

MARK = uuid.uuid4().hex[:8]
DOMAIN = f"q{MARK}.example"
OUT = f"o{MARK}.example"
IP, SIMILAR_IP = "192.0.2.4", "192.0.2.45"
AT = datetime(2020, 5, 10, 12, 0, 0)
RANGE = {"start_date": "2020-05-01", "end_date": "2020-05-20"}

# name: (sender, recipient, ip)
MESSAGES = {
    "dom-billing": (f"billing@{DOMAIN}", f"to@{OUT}", None),
    "dom-other": (f"other@{DOMAIN}", f"to@{OUT}", None),
    "ip-billing": (f"billing@{OUT}", f"to@{OUT}", IP),
    "ip-other": (f"other@{OUT}", f"to@{OUT}", IP),
    "similar-billing": (f"billing@{OUT}", f"to@{OUT}", SIMILAR_IP),
}


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


@pytest.fixture()
def api(monkeypatch):
    for key in ('auth_enabled', 'basic_auth_enabled', 'oauth2_enabled'):
        monkeypatch.setattr(settings._inner, key, False)
    monkeypatch.setattr(settings._inner, 'disabled_features', '')
    monkeypatch.setattr(settings._inner, 'blacklist_emails', '')
    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app)


# ---------------------------------------------------------------- Messages exact_ip

def _cleanup():
    from app.database import get_db_context
    from app.models import MessageCorrelation, RspamdLog
    with get_db_context() as db:
        db.query(MessageCorrelation).filter(MessageCorrelation.correlation_key.like(f"{MARK}-%")).delete(synchronize_session=False)
        db.query(RspamdLog).filter(RspamdLog.correlation_key.like(f"{MARK}-%")).delete(synchronize_session=False)
        db.commit()


@pytest.fixture()
def mail(api):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import init_db, get_db_context
    from app.models import MessageCorrelation, RspamdLog
    init_db()
    _cleanup()
    with get_db_context() as db:
        for i, (name, (sender, recipient, ip)) in enumerate(MESSAGES.items()):
            scan_id = None
            if ip:
                scan = RspamdLog(time=AT + timedelta(minutes=i), ip=ip, correlation_key=f"{MARK}-{name}")
                db.add(scan)
                db.flush()
                scan_id = scan.id
            db.add(MessageCorrelation(correlation_key=f"{MARK}-{name}", message_id=f"<{name}.{MARK}@example.com>",
                                      sender=sender, recipient=recipient, subject=f"{name} {MARK}",
                                      direction="outbound", final_status="delivered",
                                      first_seen=AT + timedelta(minutes=i), last_seen=AT + timedelta(minutes=i),
                                      created_at=AT, rspamd_log_id=scan_id))
        db.commit()
    yield api
    _cleanup()


def _names(rows):
    return sorted(r.split()[0] for r in rows if MARK in (r or ""))


CASES = [
    # A domain card's list with a partial sender added: billing matches billing@<domain>
    ({"domain": DOMAIN, "sender": "billing"}, ["dom-billing"]),
    # An IP card's: the IP whole (not 192.0.2.45), the sender a part
    ({"ip": IP, "exact_ip": "true", "sender": "billing"}, ["ip-billing"]),
    ({"ip": IP, "exact_ip": "true"}, ["ip-billing", "ip-other"]),
    # Without it, the IP is a part as always
    ({"ip": IP, "sender": "billing"}, ["ip-billing", "similar-billing"]),
    # The generic exact still makes every filter whole (L1's API)
    ({"ip": IP, "exact": "true", "sender": "billing"}, []),
]


@pytest.mark.parametrize("filters,expected", CASES)
def test_exact_ip_in_the_list_counts_new_mail_and_export(mail, filters, expected):
    params = {**RANGE, **filters}
    res = mail.get("/api/messages", params=params)
    assert res.status_code == 200, res.text
    assert _names(m["subject"] for m in res.json()["data"]) == expected
    facets = mail.get("/api/messages/facets", params=params).json()
    assert facets["status"]["delivered"] == len(expected)
    assert mail.get("/api/messages/new", params={"after_id": 0, **params}).json()["count"] == len(expected)
    exported = mail.get("/api/export/messages/csv", params=params)
    if not expected:
        assert exported.status_code == 404
    else:
        assert exported.status_code == 200, exported.text
        rows = csv.DictReader(io.StringIO(exported.content.decode("utf-8-sig")))
        assert _names(r["Subject"] for r in rows) == expected


def test_exact_ip_is_documented(api):
    schema = api.app.openapi()
    for path in ("/api/messages", "/api/messages/facets", "/api/messages/new", "/api/export/messages/csv"):
        names = [p["name"] for p in schema["paths"][path]["get"]["parameters"]]
        assert "exact_ip" in names, path


# ---------------------------------------------------------------- the manual Run of the blocklist job

@pytest.fixture()
def statuses():
    saved = {k: dict(v) for k, v in scheduler.job_status.items()}
    yield scheduler.job_status
    scheduler.job_status.clear()
    scheduler.job_status.update(saved)


class _Busy:
    def locked(self):
        return True


def test_run_while_a_single_address_check_holds_the_lock_is_refused(api, statuses, monkeypatch):
    before = {'last_run': None, 'status': 'success', 'error': None}
    statuses['blacklist_check'] = dict(before)
    started = []

    async def job(**kwargs):
        started.append(kwargs)

    monkeypatch.setattr(scheduler, 'blacklist_check_lock', lambda: _Busy())
    monkeypatch.setattr(scheduler, 'check_monitored_hosts_job', job)
    res = api.post("/api/settings/jobs/blacklist_check/run")
    assert res.status_code == 409, res.text
    assert res.json()["detail"] == "A blocklist check is already running. Try again when it is done."
    assert started == []
    assert statuses['blacklist_check'] == before, "not marked running"


@pytest.mark.parametrize("holder,restored", [("host", True), (None, True), ("full", False)])
def test_a_run_that_skipped_for_a_single_address_check_leaves_the_status_as_it_was(api, statuses, monkeypatch, holder, restored):
    """The check of one address took the lock after the Run was accepted: the
    job skips, and no run of the job is there to set its status."""
    before = {'last_run': datetime(2026, 10, 27, 6, 0), 'status': 'success', 'error': None}
    statuses['blacklist_check'] = dict(before)

    async def job(**kwargs):
        return scheduler.JOB_SKIPPED

    monkeypatch.setattr(scheduler, 'check_monitored_hosts_job', job)
    monkeypatch.setattr(scheduler, 'blacklist_check_holder', lambda: holder)
    res = api.post("/api/settings/jobs/blacklist_check/run")
    assert res.status_code == 200, res.text
    if restored:
        assert statuses['blacklist_check'] == before
        # and the next Run is not refused as "already running"
        assert api.post("/api/settings/jobs/blacklist_check/run").status_code == 200
    else:
        # A full scan holds the job: it sets the status when it ends
        assert statuses['blacklist_check']['status'] == 'running'


# ---------------------------------------------------------------- the scheduled scan and a single address check

@pytest.fixture()
def scan(monkeypatch):
    monkeypatch.setattr(settings._inner, 'disabled_features', '')
    monkeypatch.setattr(scheduler, '_blacklist_check_lock', asyncio.Lock())
    ran = []

    async def run(force, send_notification):
        ran.append(scheduler.blacklist_check_holder())

    monkeypatch.setattr(scheduler, '_run_check_monitored_hosts', run)
    return ran


def test_the_scan_waits_for_a_single_address_check_and_then_runs(scan):
    async def main():
        async with scheduler.blacklist_check_hold('host'):
            job = asyncio.create_task(scheduler.check_monitored_hosts_job())
            await asyncio.sleep(0.8)
            assert scan == [] and not job.done(), "it waits while the address is checked"
        result = await asyncio.wait_for(job, 5)
        assert result != scheduler.JOB_SKIPPED
        assert scan == ['full']
        assert scheduler.blacklist_check_holder() is None
    asyncio.run(main())


def test_the_scan_skips_while_another_full_scan_runs(scan):
    async def main():
        async with scheduler.blacklist_check_hold('full'):
            result = await asyncio.wait_for(scheduler.check_monitored_hosts_job(), 2)
        assert result == scheduler.JOB_SKIPPED
        assert scan == []
    asyncio.run(main())


def test_the_wait_for_a_single_address_check_is_bounded(scan, monkeypatch):
    monkeypatch.setattr(scheduler, 'BLACKLIST_HOST_WAIT_SECONDS', 0.6)

    async def main():
        async with scheduler.blacklist_check_hold('host'):
            result = await asyncio.wait_for(scheduler.check_monitored_hosts_job(), 5)
        assert result == scheduler.JOB_SKIPPED
        assert scan == []
    asyncio.run(main())
