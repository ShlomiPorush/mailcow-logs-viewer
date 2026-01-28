"""
DMARC Notification Module
Uses the global SMTP service to send DMARC-specific notifications
"""
import logging
from typing import List, Dict
from datetime import datetime

from ..config import settings
from .smtp_service import send_notification_email, get_notification_email

logger = logging.getLogger(__name__)


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
    
    # Get recipient: DMARC_ERROR_EMAIL or fallback to ADMIN_EMAIL
    recipient = get_notification_email(settings.dmarc_error_email)
    
    if not recipient:
        logger.warning("No recipient configured (DMARC_ERROR_EMAIL or ADMIN_EMAIL)")
        return False
    
    # Build email content
    subject = f"DMARC Processing Errors - Sync #{sync_id}"
    text_content = _create_text_content(failed_emails, sync_id)
    html_content = _create_html_content(failed_emails, sync_id)
    
    # Send via global SMTP service
    return send_notification_email(recipient, subject, text_content, html_content)


def _create_text_content(failed_emails: List[Dict], sync_id: int) -> str:
    """Create plain text email content"""
    lines = [
        f"DMARC Report Processing Errors - Sync #{sync_id}",
        f"Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
        f"Failed to process {len(failed_emails)} DMARC report email(s):",
        ""
    ]
    
    for i, email_data in enumerate(failed_emails, 1):
        lines.append(f"{i}. Email ID: {email_data.get('email_id', 'unknown')}")
        lines.append(f"   Message-ID: {email_data.get('message_id', 'unknown')}")
        lines.append(f"   Subject: {email_data.get('subject', 'unknown')}")
        lines.append(f"   Error: {email_data.get('error', 'unknown')}")
        lines.append("")
    
    lines.append("---")
    lines.append("This is an automated notification from mailcow Logs Viewer")
    lines.append(f"DMARC IMAP Sync Service")
    
    return "\n".join(lines)


def _create_html_content(failed_emails: List[Dict], sync_id: int) -> str:
    """Create HTML email content"""
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
        }}
        .header {{
            background-color: #dc3545;
            color: white;
            padding: 20px;
            border-radius: 5px;
        }}
        .content {{
            padding: 20px;
        }}
        .error-list {{
            background-color: #f8f9fa;
            border-left: 4px solid #dc3545;
            padding: 15px;
            margin: 20px 0;
        }}
        .error-item {{
            margin-bottom: 20px;
            padding-bottom: 20px;
            border-bottom: 1px solid #dee2e6;
        }}
        .error-item:last-child {{
            border-bottom: none;
        }}
        .label {{
            font-weight: bold;
            color: #495057;
        }}
        .value {{
            margin-left: 10px;
            color: #212529;
        }}
        .error {{
            color: #dc3545;
            margin-top: 5px;
        }}
        .footer {{
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #dee2e6;
            font-size: 12px;
            color: #6c757d;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h2>⚠️ DMARC Processing Errors</h2>
        <p>Sync #{sync_id} - {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
    </div>
    
    <div class="content">
        <p>Failed to process <strong>{len(failed_emails)}</strong> DMARC report email(s):</p>
        
        <div class="error-list">
"""
    
    for i, email_data in enumerate(failed_emails, 1):
        html += f"""
            <div class="error-item">
                <div><span class="label">#{i}</span></div>
                <div><span class="label">Email ID:</span><span class="value">{email_data.get('email_id', 'unknown')}</span></div>
                <div><span class="label">Message-ID:</span><span class="value">{email_data.get('message_id', 'unknown')}</span></div>
                <div><span class="label">Subject:</span><span class="value">{email_data.get('subject', 'unknown')}</span></div>
                <div class="error"><span class="label">Error:</span> {email_data.get('error', 'unknown')}</div>
            </div>
"""
    
    html += """
        </div>
        
        <div class="footer">
            <p>This is an automated notification from <strong>mailcow Logs Viewer</strong></p>
            <p>DMARC IMAP Sync Service</p>
        </div>
    </div>
</body>
</html>
"""
    
    return html