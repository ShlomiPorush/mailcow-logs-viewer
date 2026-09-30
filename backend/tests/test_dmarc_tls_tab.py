"""The TLS tab of the DMARC & TLS page: each domain's TLS-RPT record status in
the domains list, and the record of one domain without the DMARC overview.
DNS is injected; no live lookups."""
import time
from datetime import datetime

import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from fastapi.testclient import TestClient

from app.routers import dmarc as dmarc_router

DOMAIN = 'tls-tab-test.example'
CACHED = {'status': 'success', 'message': 'TLS-RPT configured', 'record': 'v=TLSRPTv1; rua=mailto:tls@example.test',
          'report_uris': ['mailto:tls@example.test'], 'warnings': []}


def _client():
    from app.main import app
    return TestClient(app)


def test_the_record_comes_from_the_cached_dns_check(monkeypatch):
    async def no_live_lookup(domain):
        raise AssertionError('a cached record must not be looked up again')
    monkeypatch.setattr(dmarc_router, '_load_overview_dns', lambda domain: (None, CACHED))
    monkeypatch.setattr(dmarc_router, 'check_tls_rpt_record', no_live_lookup)
    body = _client().get(f'/api/dmarc/domains/{DOMAIN}/tls-rpt-record').json()
    assert body == {'domain': DOMAIN, 'tls_rpt_record': CACHED}


def test_a_domain_never_checked_is_looked_up_live(monkeypatch):
    looked_up = []

    async def live(domain):
        looked_up.append(domain)
        return {'status': 'warning', 'message': 'TLS-RPT record not published', 'record': None,
                'report_uris': [], 'warnings': []}
    monkeypatch.setattr(dmarc_router, '_load_overview_dns', lambda domain: (None, None))
    monkeypatch.setattr(dmarc_router, 'check_tls_rpt_record', live)
    body = _client().get(f'/api/dmarc/domains/{DOMAIN}/tls-rpt-record').json()
    assert looked_up == [DOMAIN]
    assert body['tls_rpt_record']['status'] == 'warning'


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


@pytest.fixture()
def seeded():
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.database import SessionLocal, init_db
    from app.models import DMARCReport, DomainDNSCheck
    from app.services.dmarc_cache import clear_dmarc_cache
    init_db()
    db = SessionLocal()
    checked, unchecked = f'checked.{DOMAIN}', f'unchecked.{DOMAIN}'
    now = int(time.time())

    def cleanup():
        db.query(DMARCReport).filter(DMARCReport.domain.in_([checked, unchecked])).delete(synchronize_session=False)
        db.query(DomainDNSCheck).filter(DomainDNSCheck.domain_name.in_([checked, unchecked])).delete(synchronize_session=False)
        db.commit()
        clear_dmarc_cache(db)

    cleanup()
    for name in (checked, unchecked):
        db.add(DMARCReport(domain=name, org_name='test', report_id=f'tls-tab-{name}-{now}', begin_date=now - 3600, end_date=now))
    db.add(DomainDNSCheck(domain_name=checked, checked_at=datetime.utcnow(),
                          tls_rpt_check={'status': 'warning', 'message': 'TLS-RPT record not published'}))
    db.commit()
    clear_dmarc_cache(db)
    yield checked, unchecked
    cleanup()
    db.close()


def test_the_domains_list_carries_each_domains_tls_rpt_status(seeded):
    checked, unchecked = seeded
    rows = {d['domain']: d for d in _client().get('/api/dmarc/domains').json()['domains']}
    assert rows[checked]['tls_rpt_status'] == 'warning'
    # Not checked yet: no status rather than a guess
    assert rows[unchecked]['tls_rpt_status'] is None
