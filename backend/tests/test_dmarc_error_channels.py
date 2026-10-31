"""Report emails that could not be imported are announced on the notification
channels (Slack, Telegram, ntfy...) even when no SMTP server is set up.

send_dmarc_error_notification already sends to the channels without email;
both of its callers used to skip it unless SMTP was configured.
"""
import asyncio
from types import SimpleNamespace
from unittest.mock import Mock

from app import scheduler
from app.services import notification_service
from app.services.dmarc_imap_service import DMARCImapService
from tests.test_dmarc_imap_bounces import BROKEN_REPORT, FakeImap, _SyncRecord


def _channels_only(monkeypatch):
    """A notification channel is on, SMTP is not set up."""
    monkeypatch.setattr(notification_service, "has_enabled_channels", lambda: True)
    assert not scheduler.settings.notification_smtp_configured


def test_imap_import_errors_reach_the_channels_without_smtp(monkeypatch):
    import app.services.dmarc_imap_service as imap_module
    _channels_only(monkeypatch)
    service = DMARCImapService()
    service.delete_after = False
    service.connection = FakeImap({1: BROKEN_REPORT})
    monkeypatch.setattr(service, "connect", lambda: True)
    monkeypatch.setattr(service, "select_folder", lambda: True)
    monkeypatch.setattr(service, "disconnect", lambda: None)
    monkeypatch.setattr(imap_module, "SessionLocal", Mock)
    monkeypatch.setattr(imap_module, "DMARCSync", _SyncRecord)
    monkeypatch.setattr(imap_module, "settings",
                        SimpleNamespace(dmarc_imap_batch_size=10, notification_smtp_configured=False))
    notified = []
    monkeypatch.setattr(imap_module, "send_dmarc_error_notification",
                        lambda failed, sync_id: notified.append(failed))

    result = service.sync_reports()

    assert result['reports_failed'] == 1
    assert [[e['email_id'] for e in failed] for failed in notified] == [['1']]


def test_the_notification_itself_goes_to_the_channels_without_smtp(monkeypatch):
    from app.services import dmarc_notifications
    _channels_only(monkeypatch)
    sent = []
    monkeypatch.setattr(dmarc_notifications, "notify",
                        lambda subject, text, html, email_recipient, alert_type: sent.append(alert_type)
                        or {'email': False, 'channels_sent': 1})
    failed = [{'email_id': '7', 'message_id': '<m@example.com>', 'subject': 'Report', 'error': 'Not a report'}]
    assert dmarc_notifications.send_dmarc_error_notification(failed, 5) is True
    assert sent == ['dmarc_errors']


def test_failed_import_job_reaches_the_channels_without_smtp(monkeypatch):
    _channels_only(monkeypatch)
    monkeypatch.setattr(scheduler.settings._inner, "dmarc_imap_enabled", True)
    failed = [{'email_id': '7', 'message_id': '<m@example.com>', 'subject': 'Report', 'error': 'Not a report'}]
    monkeypatch.setattr(scheduler, "sync_dmarc_reports_from_imap",
                        lambda trigger: {'status': 'error', 'error_message': 'IMAP failed',
                                         'failed_emails': failed, 'sync_id': 5})
    notified = []
    monkeypatch.setattr(scheduler, "send_dmarc_error_notification",
                        lambda emails, sync_id: notified.append((emails, sync_id)))
    saved = dict(scheduler.job_status['dmarc_imap_sync'])
    try:
        asyncio.run(scheduler.dmarc_imap_sync_job())
    finally:
        scheduler.job_status['dmarc_imap_sync'] = saved

    assert notified == [(failed, 5)]
