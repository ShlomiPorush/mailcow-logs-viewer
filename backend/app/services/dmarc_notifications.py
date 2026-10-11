"""
DMARC Notification Module
Uses the global SMTP service to send DMARC-specific notifications
"""
import logging
from typing import List, Dict

from ..config import settings
from . import email_layout as e
from .smtp_service import get_notification_email
from .notification_service import notify, any_channel_configured

logger = logging.getLogger(__name__)

_FOOTER = "Import errors go to the address set in Settings, Notifications."


def send_dmarc_error_notification(failed_emails: List[Dict], sync_id: int) -> bool:
    """
    Send notification about failed DMARC report processing
    Uses global SMTP service

    Args:
        failed_emails: List of failed email dicts with message_id, subject, error
        sync_id: ID of the sync operation

    Returns:
        True if email was sent successfully, False otherwise
    """
    if not failed_emails:
        return True

    # Recipient: DMARC_ERROR_EMAIL or fallback to ADMIN_EMAIL (webhook, if
    # configured, is notified regardless of email configuration)
    recipient = get_notification_email(settings.dmarc_error_email)
    if not recipient and not any_channel_configured():
        logger.warning("No notification channel configured (DMARC_ERROR_EMAIL/ADMIN_EMAIL or webhook)")
        return False

    subject = f"DMARC & TLS: {_title(failed_emails)}"
    text_content = _create_text_content(failed_emails, sync_id)
    html_content = _create_html_content(failed_emails, sync_id)

    results = notify(subject, text_content, html_content, email_recipient=recipient,
                     alert_type="dmarc_errors")
    return results['email'] or results['channels_sent'] > 0


def _title(failed_emails: List[Dict]) -> str:
    n = len(failed_emails)
    return f"{n} report email{'s' if n != 1 else ''} could not be imported"


def _intro(sync_id: int) -> str:
    return (f"The import from the DMARC mailbox (sync #{sync_id}) skipped these emails. "
            "The reports in them are not in the app.")


def _create_text_content(failed_emails: List[Dict], sync_id: int) -> str:
    """Create plain text email content"""
    lines = [
        _title(failed_emails),
        _intro(sync_id),
        f"Date: {e.format_date(e.local_now(), time=True)}",
        "",
    ]

    for i, email_data in enumerate(failed_emails, 1):
        lines.append(f"{i}. Email ID: {email_data.get('email_id', 'unknown')}")
        lines.append(f"   Message-ID: {email_data.get('message_id', 'unknown')}")
        lines.append(f"   Subject: {email_data.get('subject', 'unknown')}")
        lines.append(f"   Error: {email_data.get('error', 'unknown')}")
        lines.append("")

    lines.append(_FOOTER)

    return "\n".join(lines)


def _create_html_content(failed_emails: List[Dict], sync_id: int) -> str:
    """Create HTML email content. Every value comes from inbound mail (or
    describes it) - anyone who can mail the rua address chooses the Subject
    and Message-ID - and email_layout escapes all of them."""
    blocks = [
        e.panel(
            email_data.get('subject') or '(no subject)',
            e.kv([
                ('Error', email_data.get('error', 'unknown'), 'fail'),
                ('Message-ID', e.mono(email_data.get('message_id', 'unknown'))),
                ('Email ID', email_data.get('email_id', 'unknown')),
            ]),
        )
        for email_data in failed_emails
    ]
    advice = "Open the emails in the DMARC mailbox to check them."
    if settings.dmarc_manual_upload_enabled:
        advice += " If one is a valid report, you can upload it by hand on the DMARC & TLS page."
    blocks.append(e.paragraph(advice, muted=True))
    return e.render(
        title=_title(failed_emails), topic='DMARC & TLS', tone='fail',
        intro=_intro(sync_id), blocks=blocks, footer=_FOOTER)
