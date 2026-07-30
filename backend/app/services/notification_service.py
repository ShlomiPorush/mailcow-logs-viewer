"""
Unified notification dispatch - email + every enabled notification channel.

One call fans out to all configured destinations. Synchronous (smtplib +
requests) - call from a worker thread / executor, never on the event loop.
"""
import logging
from typing import Dict, Optional

from .smtp_service import send_notification_email, get_notification_email
from .notification_channels import send_to_all, has_enabled_channels

logger = logging.getLogger(__name__)


def notify(
    subject: str,
    text_content: str,
    html_content: Optional[str] = None,
    email_recipient: Optional[str] = None,
    alert_type: Optional[str] = None,
) -> Dict:
    """
    Send a notification by email and to every subscribed channel.

    Args:
        subject: Short title (email subject / notification title)
        text_content: Plain-text body (used by all channels)
        html_content: Optional HTML body (email only)
        email_recipient: Override recipient; defaults to ADMIN_EMAIL
        alert_type: Topic id (see notification_channels.ALERT_TYPES). Channels
            only receive it when they subscribe to that topic; channels with no
            subscription list receive everything.

    Returns:
        {'email': bool, 'channels_sent': int, 'channels_failed': int,
         'channels_skipped': int}
    """
    results = {"email": False, "channels_sent": 0, "channels_failed": 0, "channels_skipped": 0}

    recipient = get_notification_email(email_recipient)
    if recipient:
        results["email"] = send_notification_email(recipient, subject, text_content, html_content)

    channel_result = send_to_all(subject, text_content, alert_type=alert_type)
    results["channels_sent"] = channel_result["sent"]
    results["channels_failed"] = channel_result["failed"]
    results["channels_skipped"] = channel_result.get("skipped", 0)

    if not results["email"] and results["channels_sent"] == 0:
        logger.warning("Notification '%s' was not delivered on any channel "
                       "(no email recipient / SMTP, and no working notification channel)", subject)
    return results


def any_channel_configured() -> bool:
    """True if at least one delivery path (email or a channel) is available."""
    from ..config import settings
    return bool(settings.notification_smtp_configured) or has_enabled_channels()
