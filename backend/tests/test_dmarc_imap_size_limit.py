"""Report emails larger than 20 MB are not downloaded.

Anyone can mail the report address. Every selected message was fetched whole
and read into memory, and its attachments decoded, before any per-report
limit applied, so one very large message made the import hold all of it.
The size the server reports is now checked first; a larger message is not
downloaded and shows as a failed email with its subject, like any other
email that could not be imported.
"""
from types import SimpleNamespace
from unittest.mock import Mock

import app.services.dmarc_imap_service as imap_module
from app.services import report_store
from app.services.dmarc_imap_service import DMARCImapService
from tests.test_dmarc_imap_bounces import TLS_REPORT, _SyncRecord
from tests.test_report_raw_copy import _recording_db

MB = 1024 * 1024


class SizedImap:
    """Answers UID FETCH the way imaplib returns it, and records downloads."""

    def __init__(self, mails, sizes=None, report_size=True):
        self.mails = {str(uid): raw for uid, raw in mails.items()}
        self.sizes = {str(uid): size for uid, size in (sizes or {}).items()}
        self.report_size = report_size
        self.downloaded = []
        self.seen = set()
        self.deleted = set()

    def uid(self, command, *args):
        if command == 'SEARCH':
            unseen = [uid.encode() for uid in self.mails if uid not in self.seen and uid not in self.deleted]
            return 'OK', [b' '.join(unseen)]
        if command == 'STORE':
            (self.deleted if args[2] == '\\Deleted' else self.seen).add(args[0])
            return 'OK', [b'']
        assert command == 'FETCH', command
        uid, spec = args
        raw = self.mails[uid]
        if spec == '(RFC822.SIZE)':
            if not self.report_size:
                return 'OK', [f'1 (UID {uid})'.encode()]
            size = self.sizes.get(uid, len(raw))
            return 'OK', [f'1 (UID {uid} RFC822.SIZE {size})'.encode()]
        if spec.startswith('(BODY.PEEK[HEADER.FIELDS'):
            header = b''.join(line + b'\r\n' for line in raw.splitlines()
                              if line.lower().startswith((b'message-id:', b'subject:'))) + b'\r\n'
            return 'OK', [(f'1 (UID {uid} BODY[HEADER.FIELDS (MESSAGE-ID SUBJECT)] {{{len(header)}}}'.encode(),
                           header), b')']
        assert spec == '(BODY.PEEK[])', spec
        self.downloaded.append(uid)
        return 'OK', [(f'1 (UID {uid} BODY[] {{{len(raw)}}}'.encode(), raw), b')']

    def expunge(self):
        return 'OK', [b'']


def _process(imap, monkeypatch):
    monkeypatch.setattr(report_store, "enrich_dmarc_record", lambda row: row)
    service = DMARCImapService()
    service.connection = imap
    db, _added = _recording_db()
    return service.process_email('1', db)


def test_an_email_over_the_limit_is_not_downloaded(monkeypatch):
    imap = SizedImap({1: TLS_REPORT}, sizes={1: 35 * MB})
    result = _process(imap, monkeypatch)
    assert imap.downloaded == []
    assert result['success'] is False
    assert result['skipped'] is None
    assert "35 MB" in result['error'] and "20 MB" in result['error']
    assert result['message_id'] == '<tls-1@reporter.example.com>'
    assert result['subject'].startswith('Report Domain: example.com')


def test_an_email_at_the_limit_is_imported(monkeypatch):
    imap = SizedImap({1: TLS_REPORT}, sizes={1: 20 * MB})
    result = _process(imap, monkeypatch)
    assert imap.downloaded == ['1']
    assert result['reports_created'] == 1, result


def test_a_server_that_reports_no_size_still_imports(monkeypatch):
    imap = SizedImap({1: TLS_REPORT}, report_size=False)
    result = _process(imap, monkeypatch)
    assert imap.downloaded == ['1']
    assert result['reports_created'] == 1, result


def test_sync_reports_an_oversized_email_as_failed_and_moves_on(monkeypatch):
    service = DMARCImapService()
    service.delete_after = True
    imap = SizedImap({1: TLS_REPORT, 2: TLS_REPORT.replace(b'tls-1', b'tls-2')}, sizes={1: 25 * MB})
    service.connection = imap
    monkeypatch.setattr(service, "connect", lambda: True)
    monkeypatch.setattr(service, "select_folder", lambda: True)
    monkeypatch.setattr(service, "disconnect", lambda: None)
    monkeypatch.setattr(report_store, "enrich_dmarc_record", lambda row: row)
    monkeypatch.setattr(imap_module, "SessionLocal", Mock)
    monkeypatch.setattr(imap_module, "DMARCSync", _SyncRecord)
    monkeypatch.setattr(imap_module, "settings",
                        SimpleNamespace(dmarc_imap_batch_size=10, notification_smtp_configured=True))
    notified = []
    monkeypatch.setattr(imap_module, "send_dmarc_error_notification",
                        lambda failed, sync_id: notified.append(failed))

    result = service.sync_reports()

    assert imap.downloaded == ['2']
    assert result['reports_failed'] == 1
    assert [e['email_id'] for e in result['failed_emails']] == ['1']
    assert [[e['email_id'] for e in failed] for failed in notified] == [['1']]
    # Kept, marked as read so it is not checked again; only the imported one is deleted
    assert imap.seen == {'1'}
    assert imap.deleted == {'2'}
