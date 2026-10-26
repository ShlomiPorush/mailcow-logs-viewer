"""Every answer the DMARC & TLS calls can give, so the contract check (conftest.py,
contract.py) holds each one to /openapi.json: the answers with data and without, the
shapes that change with a parameter (insights with and without a domain, the report
list with and without a page, an upload stored or a duplicate), a database that fails
(500), deletion or upload switched off (403), an upload too large (413) and the requests
the calls refuse (400, 404, 422). DNS and the IMAP server are faked and no notification
is sent; nothing leaves the test."""
import json
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import dns.resolver
import pytest

import starlette.staticfiles as sf
_orig_init = sf.StaticFiles.__init__
sf.StaticFiles.__init__ = lambda s, *a, **k: _orig_init(s, *a, **{**k, 'check_dir': False})

from fastapi.testclient import TestClient  # noqa: E402

from app import database, scheduler  # noqa: E402
from app.app_time import day_key, epoch_day_key  # noqa: E402
from app.config import settings  # noqa: E402
from app.database import get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.routers import dmarc as dmarc_router  # noqa: E402
from app.routers import domains as domains_router  # noqa: E402
from app.services import dmarc_cache, dmarc_imap_service  # noqa: E402

MARK = uuid.uuid4().hex[:8]
DOMAIN = f'{MARK}.example'
TLS_ONLY = f'tls-{MARK}.example'
UPLOADED = f'up-{MARK}.example'
OUR_DOMAINS = (DOMAIN, TLS_ONLY, UPLOADED)
PASSING_IP, FAILING_IP = '203.0.113.5', '198.51.100.7'
# One time for the whole run, so an upload sent twice has the same content
NOW = int(datetime.now(timezone.utc).timestamp())


class _Broken:
    def __getattr__(self, name):
        raise RuntimeError('database gone')


def _broken_session():
    yield _Broken()


@contextmanager
def _broken_context():
    yield _Broken()


def _postgres_available() -> bool:
    try:
        with database.engine.connect():
            return True
    except Exception:
        return False


class _Txt:
    def __init__(self, text):
        self.strings = [text.encode()]


async def _fake_dns(query, record_type='TXT', timeout=5):
    """A DMARC record for every domain and no TLS-RPT record anywhere."""
    if query.startswith('_dmarc.'):
        return [_Txt('v=DMARC1; p=reject; rua=mailto:dmarc@example.net')]
    raise dns.resolver.NXDOMAIN()


@pytest.fixture
def client(monkeypatch):
    for key in ('auth_enabled', 'basic_auth_enabled', 'oauth2_enabled'):
        monkeypatch.setattr(settings._inner, key, False)
    monkeypatch.setattr(domains_router, 'resolve_dns_with_fallback', _fake_dns)
    # The domains list is cached in memory for 5 minutes; start each test without it
    monkeypatch.setattr(dmarc_cache, '_dmarc_cache', {})
    yield TestClient(app, raise_server_exceptions=False)
    app.dependency_overrides.pop(get_db, None)


@pytest.fixture
def rows(client):
    """Two DMARC reports and a TLS report of one domain, a TLS report of another, and the
    stored DNS check of the first; removed after the test with what the calls added."""
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    from app.models import (DMARCRecord, DMARCReport, DMARCSync, DomainDNSCheck, SystemSetting, TLSReport,
                            TLSReportPolicy)
    database.init_db()
    now = datetime.now(timezone.utc)
    stamp = int(now.timestamp())
    naive = now.replace(tzinfo=None)
    with database.get_db_context() as db:
        # Shared rows these calls change: the cache signal and the import runs
        signal = db.query(SystemSetting).filter(SystemSetting.key == 'dmarc_last_update').first()
        signal_before = (signal.value, signal.updated_at) if signal else None
        syncs_before = {row.id: (row.status, row.error_message) for row in db.query(DMARCSync)}
        policy = {'p': 'none', 'pct': '100', 'adkim': 'r', 'aspf': 'r'}
        first = DMARCReport(domain=DOMAIN, org_name='reporter.example', report_id=f'{MARK}-1', email='r@x.example',
                            begin_date=stamp - 3600, end_date=stamp, policy_published=policy, content_hash=MARK)
        # Another reporter's report with the same report ID and other content
        second = DMARCReport(domain=DOMAIN, org_name='other.example', report_id=f'{MARK}-1', email='o@x.example',
                             begin_date=stamp - 3600, end_date=stamp - 60, policy_published={'p': 'none'},
                             content_hash=MARK + 'x')
        db.add_all([first, second])
        db.flush()
        db.add_all([
            DMARCRecord(dmarc_report_id=first.id, source_ip=PASSING_IP, count=1000, disposition='none',
                        dkim_result='pass', spf_result='pass', header_from=DOMAIN, envelope_from=DOMAIN),
            DMARCRecord(dmarc_report_id=first.id, source_ip=FAILING_IP, count=3, disposition='none',
                        dkim_result='fail', spf_result='fail', header_from=DOMAIN, envelope_from='spoof.example'),
            DMARCRecord(dmarc_report_id=second.id, source_ip=PASSING_IP, count=20, disposition='none',
                        dkim_result='pass', spf_result='fail', header_from=DOMAIN, envelope_from=DOMAIN),
        ])
        tls = TLSReport(report_id=f'{MARK}-tls', organization_name='tls.example', contact_info='tls@tls.example',
                        policy_domain=DOMAIN, start_datetime=naive - timedelta(hours=1), end_datetime=naive,
                        content_hash=MARK)
        tls_only = TLSReport(report_id=f'{MARK}-tls-only', organization_name='tls.example', contact_info=None,
                             policy_domain=TLS_ONLY, start_datetime=naive - timedelta(hours=2),
                             end_datetime=naive, content_hash=MARK)
        db.add_all([tls, tls_only])
        db.flush()
        db.add_all([
            TLSReportPolicy(tls_report_id=tls.id, policy_type='sts', policy_domain=DOMAIN,
                            policy_string=['version: STSv1', 'mode: enforce'], mx_host=[f'mx.{DOMAIN}'],
                            successful_session_count=10, failed_session_count=2,
                            failure_details=[{'result-type': 'certificate-expired', 'failed-session-count': 2}]),
            TLSReportPolicy(tls_report_id=tls_only.id, policy_type='no-policy-found', policy_domain=TLS_ONLY,
                            mx_host=None, successful_session_count=0, failed_session_count=0, failure_details=None),
        ])
        # A DMARC check stored by an older version: no settings yet
        db.add(DomainDNSCheck(
            domain_name=DOMAIN, checked_at=naive,
            dmarc_check={'status': 'warning', 'message': 'DMARC policy is too weak (none)', 'record': 'v=DMARC1; p=none',
                         'policy': 'none', 'is_strong': False, 'warnings': ['Consider quarantine']},
            tls_rpt_check={'status': 'success', 'message': 'TLS-RPT configured',
                           'record': f'v=TLSRPTv1; rua=mailto:tls@{DOMAIN}',
                           'report_uris': [f'mailto:tls@{DOMAIN}'], 'warnings': []}))
        db.commit()
        ids = {'dmarc': first.id, 'tls': tls.id, 'begin': first.begin_date, 'tls_start': tls.start_datetime}
    job_before = scheduler.job_status.get('dmarc_imap_sync')
    yield ids
    if job_before is None:
        scheduler.job_status.pop('dmarc_imap_sync', None)
    else:
        scheduler.job_status['dmarc_imap_sync'] = job_before
    with database.get_db_context() as db:
        dmarc_ids = [r.id for r in db.query(DMARCReport.id).filter(DMARCReport.domain.in_(OUR_DOMAINS))]
        tls_ids = [r.id for r in db.query(TLSReport.id).filter(TLSReport.policy_domain.in_(OUR_DOMAINS))]
        db.query(DMARCRecord).filter(DMARCRecord.dmarc_report_id.in_(dmarc_ids)).delete(synchronize_session=False)
        db.query(DMARCReport).filter(DMARCReport.id.in_(dmarc_ids)).delete(synchronize_session=False)
        db.query(TLSReportPolicy).filter(TLSReportPolicy.tls_report_id.in_(tls_ids)).delete(synchronize_session=False)
        db.query(TLSReport).filter(TLSReport.id.in_(tls_ids)).delete(synchronize_session=False)
        db.query(DomainDNSCheck).filter(DomainDNSCheck.domain_name.in_(OUR_DOMAINS)).delete(synchronize_session=False)
        for row in db.query(DMARCSync):
            if row.id not in syncs_before:
                db.delete(row)
            else:
                row.status, row.error_message = syncs_before[row.id]
        row = db.query(SystemSetting).filter(SystemSetting.key == 'dmarc_last_update').first()
        if signal_before is None:
            if row is not None:
                db.delete(row)
        elif row is None:
            db.add(SystemSetting(key='dmarc_last_update', value=signal_before[0], updated_at=signal_before[1]))
        else:
            row.value, row.updated_at = signal_before
        db.commit()


# ---------------------------------------------------------------- reading

def test_domains_overview_and_records(client, rows):
    body = client.get('/api/dmarc/domains').json()
    ours = {d['domain']: d for d in body['domains'] if d['domain'] in OUR_DOMAINS}
    assert ours[DOMAIN]['has_dmarc'] and ours[DOMAIN]['dmarc_record']['policy'] == 'none'
    assert not ours[TLS_ONLY]['has_dmarc'] and ours[TLS_ONLY]['tls_rpt_record']['found'] is False
    # The second call is answered from the cache
    assert client.get('/api/dmarc/domains').status_code == 200

    overview = client.get(f'/api/dmarc/domains/{DOMAIN}/overview').json()
    assert overview['policy']['p'] == 'none' and 'settings' in overview['dmarc_record']
    empty = client.get(f'/api/dmarc/domains/{TLS_ONLY}/overview').json()
    assert empty['policy'] is None and empty['tls_rpt_record']['status'] == 'warning'
    assert client.get(f'/api/dmarc/domains/{DOMAIN}/overview?days=x').status_code == 422

    assert client.get(f'/api/dmarc/domains/{DOMAIN}/tls-rpt-record').json()['tls_rpt_record']['status'] == 'success'
    assert 'info' in client.get(f'/api/dmarc/domains/{TLS_ONLY}/tls-rpt-record').json()['tls_rpt_record']


def test_insights_with_and_without_a_domain(client, rows, monkeypatch):
    monkeypatch.setattr(settings._inner, 'dmarc_insights_min_volume', 10)
    monkeypatch.setattr(settings._inner, 'dmarc_insights_pass_threshold', 95.0)
    one = client.get(f'/api/dmarc/insights?domain={DOMAIN}').json()
    assert one['recommendations'][0]['type'] == 'tighten_policy'
    assert [s['source_ip'] for s in one['new_sources']] == [FAILING_IP]
    assert client.get(f'/api/dmarc/insights?domain={TLS_ONLY}').json()['has_data'] is False
    assert DOMAIN in [i['domain'] for i in client.get('/api/dmarc/insights').json()['insights']]


def test_report_lists(client, rows):
    assert client.get('/api/dmarc/reports/config').status_code == 200
    legacy = client.get(f'/api/dmarc/reports/all?search={MARK}').json()
    assert legacy['total'] == 4 and 'page' not in legacy
    assert any(r['shared_report_id'] for r in legacy['reports'])
    paged = client.get(f'/api/dmarc/reports/all?search={MARK}&page=1&limit=2&sort_by=records&sort_dir=asc').json()
    assert paged['total_pages'] == 2 and len(paged['reports']) == 2
    for bad in ('page=0', 'limit=0', 'sort_by=nope', 'sort_dir=up'):
        assert client.get(f'/api/dmarc/reports/all?{bad}').status_code == 422
    names = [d['domain'] for d in client.get('/api/dmarc/reports/domains').json()['domains']]
    assert DOMAIN in names and TLS_ONLY in names


def test_dmarc_days_and_sources(client, rows):
    day = epoch_day_key(rows['begin'])
    calendar = client.get(f'/api/dmarc/domains/{DOMAIN}/calendar?days=7').json()
    assert day in [d['date'] for d in calendar['days']]
    assert client.get(f'/api/dmarc/domains/{DOMAIN}/calendar').status_code == 200
    assert client.get(f'/api/dmarc/domains/{DOMAIN}/calendar?days=0').status_code == 422

    assert client.get(f'/api/dmarc/domains/{DOMAIN}/reports').json()['data'][0]['total_messages'] == 1023
    assert client.get(f'/api/dmarc/domains/{DOMAIN}/reports?limit=0').status_code == 422

    details = client.get(f'/api/dmarc/domains/{DOMAIN}/reports/{day}/details').json()
    assert details['totals']['total_messages'] == 1023
    assert client.get(f'/api/dmarc/domains/{DOMAIN}/reports/2000-01-01/details').status_code == 404
    assert client.get(f'/api/dmarc/domains/{DOMAIN}/reports/not-a-day/details').status_code == 400

    sources = client.get(f'/api/dmarc/domains/{DOMAIN}/sources').json()
    assert [s['source_ip'] for s in sources['data']] == [PASSING_IP, FAILING_IP]
    assert client.get(f'/api/dmarc/domains/{DOMAIN}/sources?page=0').status_code == 422

    source = client.get(f'/api/dmarc/domains/{DOMAIN}/sources/{PASSING_IP}/details').json()
    assert len(source['envelope_from_groups']) == 2
    assert client.get(f'/api/dmarc/domains/{DOMAIN}/sources/192.0.2.250/details').status_code == 404
    assert client.get(f'/api/dmarc/domains/{DOMAIN}/sources/{PASSING_IP}/details?days=x').status_code == 422


def test_tls_reports(client, rows):
    reports = client.get(f'/api/dmarc/domains/{DOMAIN}/tls-reports').json()
    assert reports['data'][0]['policies'][0]['failed_sessions'] == 2
    assert client.get(f'/api/dmarc/domains/{TLS_ONLY}/tls-reports').status_code == 200
    assert client.get(f'/api/dmarc/domains/{DOMAIN}/tls-reports?limit=501').status_code == 422

    day = day_key(rows['tls_start'])
    assert client.get(f'/api/dmarc/domains/{DOMAIN}/tls-reports/daily').json()['data'][0]['date'] == day
    assert client.get(f'/api/dmarc/domains/{DOMAIN}/tls-reports/daily?page=0').status_code == 422

    details = client.get(f'/api/dmarc/domains/{DOMAIN}/tls-reports/{day}/details').json()
    assert details['stats']['total_sessions'] == 12
    assert client.get(f'/api/dmarc/domains/{DOMAIN}/tls-reports/2000-01-01/details').status_code == 404
    assert client.get(f'/api/dmarc/domains/{DOMAIN}/tls-reports/31-12-2000/details').status_code == 400


# ---------------------------------------------------------------- upload and deletion

def _dmarc_xml(report_id: str, count: int) -> bytes:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <report_metadata>
    <org_name>upload.example</org_name><email>r@upload.example</email>
    <report_id>{report_id}</report_id>
    <date_range><begin>{NOW - 3600}</begin><end>{NOW}</end></date_range>
  </report_metadata>
  <policy_published><domain>{UPLOADED}</domain><p>none</p></policy_published>
  <record>
    <row><source_ip>{PASSING_IP}</source_ip><count>{count}</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
    <identifiers><header_from>{UPLOADED}</header_from></identifiers>
    <auth_results><spf><domain>{UPLOADED}</domain><result>pass</result></spf></auth_results>
  </record>
</feedback>""".encode()


def _tls_json() -> bytes:
    return json.dumps({
        'organization-name': 'tls.example', 'contact-info': 'tls@tls.example', 'report-id': f'{MARK}-up-tls',
        'date-range': {'start-datetime': '2026-01-12T00:00:00Z', 'end-datetime': '2026-01-12T23:59:59Z'},
        'policies': [{'policy': {'policy-type': 'sts', 'policy-string': ['version: STSv1'],
                                 'policy-domain': UPLOADED, 'mx-host': [f'mx.{UPLOADED}']},
                      'summary': {'total-successful-session-count': 5, 'total-failure-session-count': 0}}],
    }).encode()


def test_upload(client, rows, monkeypatch):
    monkeypatch.setattr(settings._inner, 'dmarc_manual_upload_enabled', True)

    def upload(content, name='report.xml'):
        return client.post('/api/dmarc/upload', files={'file': (name, content)})

    stored = upload(_dmarc_xml(f'{MARK}-up', 4)).json()
    assert stored['status'] == 'success' and stored['records_count'] == 1
    assert upload(_dmarc_xml(f'{MARK}-up', 4)).json()['status'] == 'duplicate'
    conflict = upload(_dmarc_xml(f'{MARK}-up', 5)).json()
    assert conflict['status'] == 'success' and 'same report ID' in conflict['message']
    assert upload(_tls_json(), 'report.json').json()['policies_count'] == 1

    assert upload(b'not a report').status_code == 400
    from app.services.safe_decompress import MAX_COMPRESSED_BYTES
    assert upload(b'x' * (MAX_COMPRESSED_BYTES + 1)).status_code == 413
    assert client.post('/api/dmarc/upload').status_code == 422
    monkeypatch.setattr(settings._inner, 'dmarc_manual_upload_enabled', False)
    assert upload(_dmarc_xml(f'{MARK}-off', 1)).status_code == 403


def test_deleting_reports(client, rows, monkeypatch):
    monkeypatch.setattr(settings._inner, 'dmarc_allow_report_delete', False)
    assert client.delete(f"/api/dmarc/reports/dmarc/{rows['dmarc']}").status_code == 403
    assert client.delete(f'/api/dmarc/reports/domains/{DOMAIN}').status_code == 403

    monkeypatch.setattr(settings._inner, 'dmarc_allow_report_delete', True)
    assert client.delete(f"/api/dmarc/reports/dmarc/{rows['dmarc']}").json()['status'] == 'success'
    assert client.delete(f"/api/dmarc/reports/tls/{rows['tls']}").json()['status'] == 'success'
    for kind in ('dmarc', 'tls'):
        assert client.delete(f'/api/dmarc/reports/{kind}/0').status_code == 404
    assert client.delete('/api/dmarc/reports/spf/1').status_code == 400
    assert client.delete('/api/dmarc/reports/dmarc/x').status_code == 422

    deleted = client.delete(f'/api/dmarc/reports/domains/{DOMAIN.upper()}').json()
    assert deleted['dmarc_reports'] == 1 and deleted['tls_reports'] == 0
    assert client.delete(f'/api/dmarc/reports/domains/{DOMAIN}').status_code == 404
    assert client.delete('/api/dmarc/reports/domains/%20').status_code == 400

    assert client.post('/api/dmarc/cache/clear').json()['status'] == 'success'


# ---------------------------------------------------------------- IMAP import

class _Imap:
    """An IMAP server holding the given mails, answering as imaplib returns it."""

    def __init__(self, mails):
        self.mails = {str(uid): raw for uid, raw in mails.items()}
        self.seen = set()

    def select(self, folder):
        return 'OK', [str(len(self.mails)).encode()]

    def uid(self, command, *args):
        if command == 'SEARCH':
            return 'OK', [b' '.join(uid.encode() for uid in self.mails if uid not in self.seen)]
        if command == 'STORE':
            self.seen.add(args[0])
            return 'OK', [b'']
        uid, spec = args
        raw = self.mails[uid]
        if spec == '(RFC822.SIZE)':
            return 'OK', [f'1 (UID {uid} RFC822.SIZE {len(raw)})'.encode()]
        if spec.startswith('(BODY.PEEK[HEADER.FIELDS'):
            header = b''.join(line + b'\r\n' for line in raw.splitlines()
                              if line.lower().startswith((b'message-id:', b'subject:'))) + b'\r\n'
            return 'OK', [(f'1 (UID {uid} BODY[HEADER.FIELDS (MESSAGE-ID SUBJECT)] {{{len(header)}}}'.encode(),
                           header), b')']
        return 'OK', [(f'1 (UID {uid} BODY[] {{{len(raw)}}}'.encode(), raw), b')']

    def expunge(self):
        return 'OK', [b'']

    def logout(self):
        return 'BYE', [b'']


BROKEN_REPORT_MAIL = f"""From: reports@reporter.example
Subject: Report Domain: {DOMAIN} Submitter: reporter.example Report-ID: broken-{MARK}
Message-ID: <broken-{MARK}@reporter.example>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="b"

--b
Content-Type: application/gzip
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="broken.xml.gz"

bm90IGd6aXA=
--b--
""".replace('\n', '\r\n').encode()


def test_imap_import(client, rows, monkeypatch):
    monkeypatch.setattr(settings._inner, 'dmarc_imap_enabled', False)
    assert client.post('/api/dmarc/imap/sync').status_code == 400
    assert client.get('/api/dmarc/imap/status').json()['configuration']['host'] is None

    for key, value in (('dmarc_imap_enabled', True), ('dmarc_imap_host', 'imap.example'), ('dmarc_imap_port', 993),
                       ('dmarc_imap_user', 'reports'), ('dmarc_imap_password', 'x'), ('dmarc_imap_folder', 'INBOX'),
                       ('dmarc_imap_delete_after', False), ('dmarc_imap_interval', 3600),
                       ('dmarc_imap_scan_all_unseen', False)):
        monkeypatch.setattr(settings._inner, key, value)
    server = _Imap({1: BROKEN_REPORT_MAIL})

    def connect(self):
        self.connection = server
        return True
    monkeypatch.setattr(dmarc_imap_service.DMARCImapService, 'connect', connect)
    sent = []
    monkeypatch.setattr(dmarc_imap_service, 'send_dmarc_error_notification',
                        lambda failed, sync_id: sent.append(sync_id) or True)

    # TestClient runs the queued import before it returns
    assert client.post('/api/dmarc/imap/sync').json()['status'] == 'started'
    assert len(sent) == 1
    history = client.get('/api/dmarc/imap/history?limit=500').json()
    run = next(r for r in history['data'] if r['id'] == sent[0])
    assert run['failed_emails'][0]['message_id'] == f'<broken-{MARK}@reporter.example>'
    assert client.get('/api/dmarc/imap/history?page=0').status_code == 422
    status = client.get('/api/dmarc/imap/status').json()
    assert status['configuration']['host'] == 'imap.example' and status['latest_sync'] is not None

    with dmarc_imap_service._sync_lock:
        assert client.post('/api/dmarc/imap/sync').json()['status'] == 'already_running'


# ---------------------------------------------------------------- failures

DB_GETS = ['/api/dmarc/insights', f'/api/dmarc/insights?domain={DOMAIN}', '/api/dmarc/reports/all',
           '/api/dmarc/reports/all?page=1', '/api/dmarc/reports/domains', f'/api/dmarc/domains/{DOMAIN}/calendar',
           f'/api/dmarc/domains/{DOMAIN}/reports', f'/api/dmarc/domains/{DOMAIN}/reports/2026-01-01/details',
           f'/api/dmarc/domains/{DOMAIN}/sources', f'/api/dmarc/domains/{DOMAIN}/sources/{PASSING_IP}/details',
           f'/api/dmarc/domains/{DOMAIN}/tls-reports', f'/api/dmarc/domains/{DOMAIN}/tls-reports/daily',
           f'/api/dmarc/domains/{DOMAIN}/tls-reports/2026-01-01/details', '/api/dmarc/imap/status',
           '/api/dmarc/imap/history']


def test_when_the_database_fails(client, monkeypatch):
    monkeypatch.setattr(settings._inner, 'dmarc_allow_report_delete', True)
    app.dependency_overrides[get_db] = _broken_session
    for path in DB_GETS:
        assert client.get(path).status_code == 500, path
    assert client.post('/api/dmarc/cache/clear').status_code == 500
    assert client.delete('/api/dmarc/reports/dmarc/1').status_code == 500
    assert client.delete(f'/api/dmarc/reports/domains/{DOMAIN}').status_code == 500

    # The calls that open their own session
    monkeypatch.setattr(dmarc_router, 'SessionLocal', _broken_context)
    assert client.get('/api/dmarc/domains').status_code == 500
    assert client.get(f'/api/dmarc/domains/{DOMAIN}/overview').status_code == 500
    monkeypatch.setattr(settings._inner, 'dmarc_manual_upload_enabled', True)
    response = client.post('/api/dmarc/upload', files={'file': ('report.xml', _dmarc_xml(f'{MARK}-gone', 1))})
    assert response.status_code == 500


def test_tls_rpt_record_when_the_session_cannot_close(client, monkeypatch):
    """The cached check is read in a session the route opens and closes itself; a
    database that drops while the session ends is a 500."""
    class Session:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            raise RuntimeError('connection lost while closing')

        def query(self, *args, **kwargs):
            raise RuntimeError('no database')

    monkeypatch.setattr(dmarc_router, 'SessionLocal', Session)
    assert client.get('/api/dmarc/domains/example.com/tls-rpt-record').status_code == 500
