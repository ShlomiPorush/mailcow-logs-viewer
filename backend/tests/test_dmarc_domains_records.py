"""The DMARC page's domains list says, for each domain, whether its DMARC and
TLS-RPT records are in place and how many senders fail DMARC; the sources say
who reported each address, for the mail flow.

A domain with a stored DNS check is read from it; one without (a domain that is
not in mailcow) is looked up live, and a lookup that fails is "not checked".
"""
import time
from datetime import datetime

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from app.database import init_db, SessionLocal
from app.models import DMARCReport, DMARCRecord, DomainDNSCheck

LIVE = 'records-live-test.example'
STORED = 'records-stored-test.example'
FAILING_IP, PASSING_IP = '192.0.2.10', '192.0.2.20'


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _cleanup(db):
    for domain in (LIVE, STORED):
        db.query(DMARCRecord).filter(DMARCRecord.dmarc_report_id.in_(
            db.query(DMARCReport.id).filter(DMARCReport.domain == domain)
        )).delete(synchronize_session=False)
        db.query(DMARCReport).filter(DMARCReport.domain == domain).delete()
    db.query(DomainDNSCheck).filter(DomainDNSCheck.domain_name == STORED).delete()
    db.commit()


@pytest.fixture()
def seeded(monkeypatch):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    init_db()
    from app.services import dmarc_cache
    monkeypatch.setattr(dmarc_cache, '_dmarc_cache', {})
    db = SessionLocal()
    _cleanup(db)
    now = int(time.time())
    for domain in (LIVE, STORED):
        for org in ('Receiver A', 'Receiver B'):
            report = DMARCReport(domain=domain, org_name=org, report_id=f'{domain}-{org}-{now}', begin_date=now - 3600, end_date=now)
            db.add(report)
            db.flush()
            # A sender that fails both, and one that passes
            db.add(DMARCRecord(dmarc_report_id=report.id, source_ip=FAILING_IP, count=5, spf_result='fail', dkim_result='fail', disposition='none'))
            db.add(DMARCRecord(dmarc_report_id=report.id, source_ip=PASSING_IP, count=20 if org == 'Receiver A' else 10, spf_result='pass', dkim_result='pass', disposition='none'))
    db.add(DomainDNSCheck(domain_name=STORED, checked_at=datetime.utcnow(),
                          dmarc_check={'status': 'warning', 'record': 'v=DMARC1; p=none', 'policy': 'none'},
                          tls_rpt_check={'status': 'success', 'record': 'v=TLSRPTv1; rua=mailto:t@example.org'}))
    db.commit()
    yield
    _cleanup(db)
    db.close()


def _client(monkeypatch, dmarc=None, tls=None, fail=False):
    from fastapi.testclient import TestClient
    from app.main import app
    from app.routers import dmarc as router
    calls = []

    async def live_dmarc(domain):
        calls.append(('dmarc', domain))
        if fail:
            raise TimeoutError('no answer')
        return dmarc

    async def live_tls(domain):
        calls.append(('tls', domain))
        if fail:
            raise TimeoutError('no answer')
        return tls
    monkeypatch.setattr(router, 'check_dmarc_record', live_dmarc)
    monkeypatch.setattr(router, 'check_tls_rpt_record', live_tls)
    return TestClient(app), calls


def _row(client, domain):
    payload = client.get('/api/dmarc/domains').json()
    return next(d for d in payload['domains'] if d['domain'] == domain)


def test_a_domain_without_a_stored_check_is_looked_up(seeded, monkeypatch):
    client, calls = _client(monkeypatch, dmarc={'status': 'success', 'record': 'v=DMARC1; p=reject', 'policy': 'reject'},
                            tls={'status': 'warning', 'record': None})
    row = _row(client, LIVE)
    assert row['dmarc_record'] == {'checked': True, 'found': True, 'status': 'success', 'policy': 'reject'}
    assert row['tls_rpt_record'] == {'checked': True, 'found': False, 'status': 'warning'}
    assert ('dmarc', LIVE) in calls and ('tls', LIVE) in calls


def test_a_domain_with_a_stored_check_is_not_looked_up(seeded, monkeypatch):
    client, calls = _client(monkeypatch)
    row = _row(client, STORED)
    assert row['dmarc_record'] == {'checked': True, 'found': True, 'status': 'warning', 'policy': 'none'}
    assert row['tls_rpt_record']['found'] is True
    assert not [c for c in calls if c[1] == STORED]


def test_a_failed_lookup_is_not_checked(seeded, monkeypatch):
    client, _ = _client(monkeypatch, fail=True)
    row = _row(client, LIVE)
    assert row['dmarc_record'] == {'checked': False, 'found': False, 'status': None, 'policy': None}
    assert row['tls_rpt_record'] == {'checked': False, 'found': False, 'status': None}


def test_senders_that_fail_dmarc_are_counted(seeded, monkeypatch):
    client, _ = _client(monkeypatch)
    assert _row(client, STORED)['failing_sources'] == 1


def test_each_address_says_who_reported_it(seeded, monkeypatch):
    client, _ = _client(monkeypatch)
    data = client.get(f'/api/dmarc/domains/{STORED}/sources').json()['data']
    passing = next(s for s in data if s['source_ip'] == PASSING_IP)
    assert passing['reporters'] == [{'org_name': 'Receiver A', 'count': 20, 'dmarc_pass': 20}, {'org_name': 'Receiver B', 'count': 10, 'dmarc_pass': 10}]
    failing = next(s for s in data if s['source_ip'] == FAILING_IP)
    assert {r['org_name']: r['dmarc_pass'] for r in failing['reporters']} == {'Receiver A': 0, 'Receiver B': 0}
