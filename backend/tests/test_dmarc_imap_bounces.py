"""
Bounces and other mail without a report in the DMARC mailbox (#417).

mailcow sends its own DMARC reports from the address that often also receives
them, so undeliverable reports come back to that mailbox. They are skipped:
not failed, no error email, never deleted, and a returned report is not imported.
"""
import base64
import gzip
from types import SimpleNamespace
from unittest.mock import Mock

from app.models import DMARCReport, TLSReport
from app.services import report_store
from app.services.dmarc_imap_service import DMARCImapService
from tests.test_report_raw_copy import dmarc_xml, tls_json, _recording_db

REPORT_XML_GZ = base64.b64encode(gzip.compress(dmarc_xml(report_id="own-outgoing").encode())).decode()

# A report this server sent, as a bounce returns it
ORIGINAL_REPORT = f"""From: "DMARC Aggregate Report" <dmarc-report@example.com>
To: dmarc@receiver.example.net
Subject: Report Domain: receiver.example.net Submitter: example.com Report-ID: own-outgoing
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="inner"

--inner
Content-Type: text/plain

This is an aggregate report from example.com.
--inner
Content-Type: application/gzip
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="example.com!receiver.example.net!1700000000!1700086400.xml.gz"

{REPORT_XML_GZ}
--inner--
"""

# Standard delivery status notification (RFC 3464) with the full original attached
DSN = f"""Return-Path: <>
From: Mail Delivery Subsystem <mailer-daemon@receiver.example.net>
To: dmarc-report@example.com
Subject: Delivery Status Notification (Failure)
Message-ID: <dsn-1@receiver.example.net>
MIME-Version: 1.0
Content-Type: multipart/report; report-type=delivery-status; boundary="outer"

--outer
Content-Type: text/plain

Your message could not be delivered: mailbox full.
--outer
Content-Type: message/delivery-status

Reporting-MTA: dns; receiver.example.net

Final-Recipient: rfc822; dmarc@receiver.example.net
Action: failed
Status: 5.2.2
--outer
Content-Type: message/rfc822

{ORIGINAL_REPORT}
--outer--
""".encode()

# Non-standard bounce as sent by aliyun.com: multipart/mixed, Chinese subject, original as a file
ALIYUN_BOUNCE = f"""Return-Path: <>
From: <postmaster@aliyun.com>
To: <dmarc-report@example.com>
Subject: =?UTF-8?B?5p2l6IeqcG9zdG1hc3RlckBhbGl5dW4uY29t55qE6YCA5L+h?=
Message-ID: <bounce-2.postmaster@aliyun.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="outer"

--outer
Content-Type: text/plain; charset=UTF-8

Mailbox full.
--outer
Content-Type: application/octet-stream
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="Report Domain_ receiver.example.net.eml"

{base64.b64encode(ORIGINAL_REPORT.encode()).decode()}
--outer--
""".encode()

TLS_REPORT = f"""From: tls-reports@reporter.example.com
To: dmarc@example.com
Subject: Report Domain: example.com Submitter: reporter.example.com Report-ID: <tls-1>
Message-ID: <tls-1@reporter.example.com>
MIME-Version: 1.0
Content-Type: multipart/report; report-type=tlsrpt; boundary="outer"

--outer
Content-Type: text/plain

This is an aggregate TLS report.
--outer
Content-Type: application/tlsrpt+gzip
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="reporter.example.com!example.com!1700000000!1700086400.json.gz"

{base64.b64encode(gzip.compress(tls_json(report_id="tls-1").encode())).decode()}
--outer--
""".encode()

BROKEN_REPORT = f"""From: reports@reporter.example.com
To: dmarc@example.com
Subject: Report Domain: example.com Submitter: reporter.example.com Report-ID: broken
Message-ID: <broken@reporter.example.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="outer"

--outer
Content-Type: text/plain

Report attached.
--outer
Content-Type: application/gzip
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="broken.xml.gz"

{base64.b64encode(b"not gzip").decode()}
--outer--
""".encode()


class FakeImap:
    """Answers UID SEARCH/FETCH/STORE like an IMAP server holding the given mails."""

    def __init__(self, mails):
        self.mails = {str(uid).encode(): raw for uid, raw in mails.items()}
        self.seen = set()
        self.deleted = set()

    def uid(self, command, *args):
        if command == 'SEARCH':
            unseen = [uid for uid in self.mails if uid not in self.seen and uid not in self.deleted]
            return 'OK', [b' '.join(unseen)]
        if command == 'FETCH':
            return 'OK', [(b'', self.mails[args[0].encode()])]
        if command == 'STORE':
            flags = self.deleted if args[2] == '\\Deleted' else self.seen
            flags.add(args[0].encode())
            return 'OK', [b'']
        raise AssertionError(command)

    def expunge(self):
        return 'OK', [b'']


def _process(raw, monkeypatch):
    import app.services.dmarc_imap_service as imap_module
    monkeypatch.setattr(report_store, "enrich_dmarc_record", lambda row: row)
    service = DMARCImapService()
    service.connection = FakeImap({1: raw})
    db, added = _recording_db()
    return service.process_email('1', db), added


def test_standard_bounce_is_skipped_and_its_report_not_imported(monkeypatch):
    result, added = _process(DSN, monkeypatch)
    assert result['skipped'] == 'bounce'
    assert result['error'] is None
    assert added == []


def test_non_standard_bounce_is_skipped(monkeypatch):
    result, added = _process(ALIYUN_BOUNCE, monkeypatch)
    assert result['skipped'] == 'no report attached'
    assert result['error'] is None
    assert added == []


def test_tls_report_is_not_taken_for_a_bounce(monkeypatch):
    result, added = _process(TLS_REPORT, monkeypatch)
    assert result['skipped'] is None
    assert result['report_type'] == 'tls-rpt'
    assert result['reports_created'] == 1, result
    assert [type(row) for row in added if isinstance(row, (TLSReport, DMARCReport))] == [TLSReport]


def test_unreadable_report_still_fails(monkeypatch):
    result, _ = _process(BROKEN_REPORT, monkeypatch)
    assert result['skipped'] is None
    assert result['success'] is False
    assert result['error']


class _SyncRecord(SimpleNamespace):
    def __init__(self, **kwargs):
        super().__init__(id=1, emails_found=0, emails_processed=0, reports_created=0,
                         reports_duplicate=0, reports_failed=0, error_message=None,
                         failed_emails=None, completed_at=None, **kwargs)


def test_sync_skips_bounces_without_failing_or_deleting(monkeypatch):
    import app.services.dmarc_imap_service as imap_module
    service = DMARCImapService()
    service.delete_after = True
    imap = FakeImap({1: DSN, 2: ALIYUN_BOUNCE, 3: BROKEN_REPORT})
    service.connection = imap
    monkeypatch.setattr(service, "connect", lambda: True)
    monkeypatch.setattr(service, "select_folder", lambda: True)
    monkeypatch.setattr(service, "disconnect", lambda: None)
    monkeypatch.setattr(imap_module, "SessionLocal", Mock)
    monkeypatch.setattr(imap_module, "DMARCSync", _SyncRecord)
    monkeypatch.setattr(imap_module, "settings",
                        SimpleNamespace(dmarc_imap_batch_size=10, notification_smtp_configured=True))
    notified = []
    monkeypatch.setattr(imap_module, "send_dmarc_error_notification",
                        lambda failed, sync_id: notified.append(failed))

    result = service.sync_reports()

    assert result['status'] == 'success'
    assert result['emails_processed'] == 3
    assert result['reports_failed'] == 1
    assert [e['email_id'] for e in result['failed_emails']] == ['3']
    assert [[e['email_id'] for e in failed] for failed in notified] == [['3']]
    assert imap.seen == {b'1', b'2', b'3'}
    assert imap.deleted == set()
