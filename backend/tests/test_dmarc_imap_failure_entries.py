"""One report email must not cost an IMAP import its failure records.

Anyone can mail the report address. The import keeps, for each email it could
not import, the email's Message-ID, Subject and error (which names the
attachment) and announces them at the end. A Subject with raw 8-bit bytes
comes back from the email parser as a Header object, and an attachment name
can decode to NUL: either one made the final commit fail, so the run lost
every failure entry, stayed 'running' and sent no notification, while the
emails were already marked as read and never tried again.

Each failure entry is now plain bounded text, it is stored before its email
is marked, and an import that fails still records and reports what failed.
"""
import base64
from types import SimpleNamespace

import pytest

from app.models import DMARCSync
from app.services import report_store
from tests.test_dmarc_imap_bounces import FakeImap


def _postgres_available() -> bool:
    try:
        from app.database import engine
        with engine.connect():
            return True
    except Exception:
        return False


def _mail(subject: bytes, disposition: bytes, content_type: bytes, body: bytes, message_id: bytes) -> bytes:
    return (
        b"From: reports@reporter.example.com\r\n"
        b"Subject: " + subject + b"\r\n"
        b"Message-ID: <" + message_id + b"@reporter.example.com>\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n"
        b"--b\r\nContent-Type: " + content_type + b"\r\nContent-Transfer-Encoding: base64\r\n"
        b"Content-Disposition: attachment; " + disposition + b"\r\n\r\n"
        + base64.b64encode(body) + b"\r\n--b--\r\n"
    )


# An ordinary reporter's email whose report is broken
ORDINARY = _mail(b"Report Domain: example.com Submitter: reporter.example.com Report-ID: r1",
                 b'filename="report.xml.gz"', b"application/gzip", b"not gzip", b"r1")
# The attachment name decodes to NUL (RFC 2231)
NUL_NAME = _mail(b"TLS Report Domain: example.com", b"filename*=utf-8''r%00.json",
                 b"application/json", b"{not json", b"nul")
# A Subject with a raw 8-bit byte
EIGHT_BIT = _mail(b"DMARC \xff report", b'filename="a.xml"', b"application/xml", b"not xml", b"8bit")


@pytest.fixture()
def run(monkeypatch):
    if not _postgres_available():
        pytest.skip('PostgreSQL not available')
    import app.services.dmarc_imap_service as imap_module
    from app.database import SessionLocal, init_db
    init_db()
    monkeypatch.setattr(report_store, "enrich_dmarc_record", lambda row: row)
    notified = []
    monkeypatch.setattr(imap_module, "send_dmarc_error_notification",
                        lambda failed, sync_id: notified.append((failed, sync_id)) or True)
    sync_ids = []

    def sync(mails, fail_after_first_batch=False):
        service = imap_module.DMARCImapService()
        service.delete_after = False
        service.scan_all_unseen = False
        imap = FakeImap(mails)
        service.connection = imap
        monkeypatch.setattr(service, "connect", lambda: True)
        monkeypatch.setattr(service, "select_folder", lambda: True)
        monkeypatch.setattr(service, "disconnect", lambda: None)
        if fail_after_first_batch:
            searches = []
            real_search = service.search_dmarc_emails

            def search():
                searches.append(1)
                if len(searches) > 2:
                    raise RuntimeError("IMAP connection lost")
                return real_search()
            monkeypatch.setattr(service, "search_dmarc_emails", search)
        result = service.sync_reports()
        with SessionLocal() as db:
            row = db.query(DMARCSync).order_by(DMARCSync.id.desc()).first()
            sync_ids.append(row.id)
            db.expunge(row)
        return SimpleNamespace(result=result, row=row, seen=sorted(imap.seen))
    sync.notified = notified
    yield sync
    with SessionLocal() as db:
        db.query(DMARCSync).filter(DMARCSync.id.in_(sync_ids)).delete(synchronize_session=False)
        db.commit()


@pytest.mark.parametrize("poison", [NUL_NAME, EIGHT_BIT], ids=["nul-attachment-name", "8-bit-subject"])
def test_one_email_cannot_cost_the_run_its_failure_records(run, poison):
    done = run({1: ORDINARY, 2: poison})

    assert done.result['status'] == 'success'
    assert done.row.status == 'success'
    assert [e['email_id'] for e in done.row.failed_emails] == ['1', '2']
    assert done.row.reports_failed == 2 and done.row.emails_processed == 2
    assert done.seen == [b'1', b'2']
    assert [[e['email_id'] for e in failed] for failed, _ in run.notified] == [['1', '2']]
    for entry in done.row.failed_emails:
        assert all(isinstance(v, str) and '\x00' not in v for v in entry.values())


def test_the_entry_keeps_readable_text(run):
    done = run({1: EIGHT_BIT, 2: NUL_NAME})
    eight_bit, nul_name = done.row.failed_emails
    assert eight_bit['subject'] == 'DMARC \ufffd report'
    assert eight_bit['message_id'] == '<8bit@reporter.example.com>'
    assert 'r.json' in nul_name['error']


def test_an_entry_the_database_still_refuses_keeps_the_email_and_the_counts(run, monkeypatch):
    import app.services.dmarc_imap_service as imap_module
    # As before the fix: the raw header goes into the entry as it is
    monkeypatch.setattr(imap_module, "_plain_text", lambda value, limit=1000: value)
    monkeypatch.setattr(imap_module, "_header_text", lambda msg, name: msg.get(name))

    done = run({1: ORDINARY, 2: EIGHT_BIT})

    assert done.row.status == 'success'
    assert done.row.reports_failed == 2 and done.row.emails_processed == 2
    assert done.row.failed_emails[0]['email_id'] == '1'
    assert done.row.failed_emails[1] == {'email_id': '2', 'message_id': None, 'subject': None,
                                         'error': imap_module._DETAILS_NOT_STORED}
    assert done.seen == [b'1', b'2']
    assert len(run.notified) == 1


def test_a_failed_import_records_and_reports_what_failed(run):
    done = run({1: ORDINARY, 2: NUL_NAME}, fail_after_first_batch=True)

    assert done.result['status'] == 'error'
    assert done.result['notified'] is True
    assert done.row.status == 'error'
    assert done.row.error_message == 'IMAP connection lost'
    assert [e['email_id'] for e in done.row.failed_emails] == ['1', '2']
    assert done.row.emails_processed == 2
    assert [[e['email_id'] for e in failed] for failed, _ in run.notified] == [['1', '2']]


def test_failures_reported_before_a_late_error_are_reported_once(run, monkeypatch):
    import app.services.dmarc_imap_service as imap_module
    real_build = imap_module.DMARCImapService._build_result
    calls = []

    def build(self, sync_record):
        # The success path fails at its very end, after its notification
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("late failure")
        return real_build(self, sync_record)
    monkeypatch.setattr(imap_module.DMARCImapService, "_build_result", build)

    done = run({1: ORDINARY})

    assert done.result['status'] == 'error' and done.result['notified'] is True
    assert len(run.notified) == 1


def test_the_job_does_not_report_failures_the_import_already_reported(monkeypatch):
    import asyncio
    from unittest.mock import Mock
    from app import scheduler
    monkeypatch.setattr(scheduler.settings._inner, "dmarc_imap_enabled", True)
    monkeypatch.setattr(type(scheduler.settings._inner), "is_feature_enabled", lambda self, name: True)
    failed = [{'email_id': '7', 'message_id': '<m@example.com>', 'subject': 'Report', 'error': 'Not a report'}]
    monkeypatch.setattr(scheduler, "sync_dmarc_reports_from_imap",
                        lambda trigger: {'status': 'error', 'error_message': 'IMAP failed',
                                         'failed_emails': failed, 'sync_id': 5, 'notified': True})
    notify = Mock()
    monkeypatch.setattr(scheduler, "send_dmarc_error_notification", notify)
    saved = dict(scheduler.job_status['dmarc_imap_sync'])
    try:
        asyncio.run(scheduler.dmarc_imap_sync_job())
    finally:
        scheduler.job_status['dmarc_imap_sync'] = saved
    notify.assert_not_called()
