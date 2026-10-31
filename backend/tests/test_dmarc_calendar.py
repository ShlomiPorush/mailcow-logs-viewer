"""The DMARC calendar of a domain: days of the app's zone (the clocks changing
too), whole days at its ends, each day the same as that day's own view, a day
without reports absent and a day where all failed present, one query whatever
the number of reports, and a year of reports answered quickly."""
import time
import uuid
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app.config import settings

MARK = uuid.uuid4().hex[:8]
DOMAIN = f'cal-{MARK}.example'
BERLIN = ZoneInfo('Europe/Berlin')
# Today, for the calendar: Wednesday 28 October 2026 in Berlin (the clocks went back on the 25th)
NOW = datetime(2026, 10, 28, 12, 0, tzinfo=BERLIN)


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


@pytest.fixture()
def db_ready(monkeypatch):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import init_db, get_db_context
    from app.models import DMARCRecord, DMARCReport
    from app.routers import dmarc as dmarc_router
    init_db()
    monkeypatch.setattr(settings._inner, 'tz', 'Europe/Berlin')
    monkeypatch.setattr(settings._inner, 'dmarc_retention_days', 60)
    monkeypatch.setattr(dmarc_router, 'local_now', lambda: NOW)

    def cleanup():
        with get_db_context() as db:
            ids = [r.id for r in db.query(DMARCReport.id).filter(DMARCReport.domain.like(f'%{MARK}%'))]
            if ids:
                db.query(DMARCRecord).filter(DMARCRecord.dmarc_report_id.in_(ids)).delete(synchronize_session=False)
                db.query(DMARCReport).filter(DMARCReport.id.in_(ids)).delete(synchronize_session=False)
            db.commit()
    cleanup()
    yield
    cleanup()


def _client():
    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app)


def _report(at_utc, records, domain=DOMAIN):
    """A report that began at at_utc with records [(count, spf, dkim)]."""
    from app.database import get_db_context
    from app.models import DMARCRecord, DMARCReport
    begin = int(at_utc.replace(tzinfo=timezone.utc).timestamp())
    with get_db_context() as db:
        report = DMARCReport(report_id=uuid.uuid4().hex, domain=domain, org_name='google.com', begin_date=begin, end_date=begin + 86399)
        db.add(report)
        db.flush()
        for count, spf, dkim in records:
            db.add(DMARCRecord(dmarc_report_id=report.id, source_ip='192.0.2.1', count=count, spf_result=spf, dkim_result=dkim))
        db.commit()


def _days(answer):
    return {d['date']: (d['total'], d['pass'], d['fail']) for d in answer['days']}


def test_days_are_the_app_zones_whole_days_and_each_equals_its_own_view(db_ready):
    # 22:30 UTC on 24 October is 00:30 on the 25th in Berlin (summer time), 23:30 UTC on the 25th is 00:30 on the 26th (winter time)
    _report(datetime(2026, 10, 24, 22, 30), [(10, 'pass', 'fail'), (5, 'fail', 'fail')])
    _report(datetime(2026, 10, 25, 23, 30), [(4, 'fail', 'pass')])
    _report(datetime(2026, 10, 24, 21, 30), [(3, 'fail', 'fail')])   # 23:30 on the 24th in Berlin: all failed
    c = _client()
    answer = c.get(f'/api/dmarc/domains/{DOMAIN}/calendar').json()
    days = _days(answer)
    assert days == {'2026-10-24': (3, 0, 3), '2026-10-25': (15, 10, 5), '2026-10-26': (4, 4, 0)}, days
    assert (answer['from'], answer['to'], answer['retention_days']) == ('2026-08-30', '2026-10-28', 60)
    assert answer['maybe_incomplete_before'] == '2026-08-30'
    for date, (total, ok, _) in days.items():
        view = c.get(f'/api/dmarc/domains/{DOMAIN}/reports/{date}/details').json()
        assert view['totals']['total_messages'] == total, date


def test_the_first_day_is_whole_and_the_day_before_it_is_out(db_ready):
    c = _client()
    # The first day of a 3-day calendar is Monday 26 October: from 00:00 Berlin (23:00 UTC on the 25th)
    _report(datetime(2026, 10, 25, 23, 5), [(7, 'pass', 'pass')])    # 00:05 on the 26th: in
    _report(datetime(2026, 10, 25, 22, 55), [(9, 'pass', 'pass')])   # 23:55 on the 25th: out
    answer = c.get(f'/api/dmarc/domains/{DOMAIN}/calendar', params={'days': 3}).json()
    assert answer['from'] == '2026-10-26' and _days(answer) == {'2026-10-26': (7, 7, 0)}


def test_one_query_whatever_the_number_of_reports(db_ready):
    from sqlalchemy import event
    from app.database import engine
    for i in range(40):
        _report(datetime(2026, 10, 1 + i % 25, 12), [(1, 'pass', 'pass'), (2, 'fail', 'fail')])
    statements = []
    listener = lambda conn, cursor, statement, *a: statements.append(statement) if 'dmarc_records' in statement else None
    event.listen(engine, 'before_cursor_execute', listener)
    try:
        answer = _client().get(f'/api/dmarc/domains/{DOMAIN}/calendar').json()
    finally:
        event.remove(engine, 'before_cursor_execute', listener)
    assert sum(t for t, _, _ in _days(answer).values()) == 120
    assert len(statements) == 1, statements


def test_bad_ranges_are_refused(db_ready):
    c = _client()
    assert c.get(f'/api/dmarc/domains/{DOMAIN}/calendar', params={'days': 0}).status_code == 422
    assert c.get(f'/api/dmarc/domains/{DOMAIN}/calendar', params={'days': 401}).status_code == 422
    assert c.get(f'/api/dmarc/domains/{DOMAIN}/calendar', params={'days': 400}).json()['from'] == '2025-09-24'


def test_a_year_of_reports_is_answered_within_a_second(db_ready):
    """20,000 reports with 10 records each, over a year."""
    from sqlalchemy import text
    from app.database import engine
    start = int(datetime(2025, 10, 29, tzinfo=timezone.utc).timestamp())
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO dmarc_reports (report_id, domain, org_name, begin_date, end_date, created_at, updated_at)
            SELECT :mark || '-' || g, :domain, 'org-' || (g % 7), :start + (g % 365) * 86400 + (g % 86400), :start + (g % 365) * 86400 + 86399, now(), now()
            FROM generate_series(1, 20000) AS g"""), {'mark': MARK, 'domain': DOMAIN, 'start': start})
        conn.execute(text("""
            INSERT INTO dmarc_records (dmarc_report_id, source_ip, count, spf_result, dkim_result, created_at)
            SELECT r.id, '192.0.2.' || k, 1 + k, CASE WHEN k % 3 = 0 THEN 'fail' ELSE 'pass' END, 'fail', now()
            FROM dmarc_reports r, generate_series(1, 10) AS k WHERE r.domain = :domain"""), {'domain': DOMAIN})
        conn.execute(text('ANALYZE dmarc_reports; ANALYZE dmarc_records'))
    c = _client()
    c.get(f'/api/dmarc/domains/{DOMAIN}/calendar', params={'days': 365})   # a warm cache, as on a page in use
    began = time.monotonic()
    answer = c.get(f'/api/dmarc/domains/{DOMAIN}/calendar', params={'days': 365}).json()
    took = time.monotonic() - began
    assert len(answer['days']) >= 360
    assert took < 1.0, f'{took:.2f} s'
