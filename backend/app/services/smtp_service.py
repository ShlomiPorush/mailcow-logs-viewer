"""
Global SMTP Service
Generic email notification service for all system modules
"""
import logging
import re
import smtplib
from email.mime.image import MIMEImage
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import List, Optional

from ..config import settings
from .mail_tls import mail_tls_context, certificate_error_hint

logger = logging.getLogger(__name__)

# The address settings (ADMIN_EMAIL, BLACKLIST_ALERT_EMAIL, DMARC_ERROR_EMAIL)
# take one or more addresses, separated by commas, semicolons or spaces.
_ADDRESS = re.compile(r'^[^@\s,;<>"]+@[^@\s,;<>"]+\.[^@\s,;<>".]+$')


def split_addresses(value: Optional[str]) -> List[str]:
    """Every entry in an address setting, valid or not."""
    return [part for part in re.split(r'[,;\s]+', value or '') if part]


def invalid_addresses(value: Optional[str]) -> List[str]:
    """Entries of an address setting that are not an email address."""
    return [part for part in split_addresses(value) if not _ADDRESS.match(part)]


def parse_recipients(value: Optional[str]) -> List[str]:
    """The valid addresses of an address setting, each once."""
    seen, recipients = set(), []
    for part in split_addresses(value):
        if _ADDRESS.match(part) and part.lower() not in seen:
            seen.add(part.lower())
            recipients.append(part)
    return recipients


def build_message(sender: str, recipient: str, subject: str, text_content: str,
                  html_content: Optional[str] = None) -> MIMEMultipart:
    """The plain text and, when given, the HTML as alternatives. HTML that
    shows the app icon (cid:app-icon) carries the icon with it."""
    from .email_layout import APP_ICON_CID, app_icon

    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = recipient

    # UTF-8 parts are base64 encoded: SMTP allows at most 998 characters per
    # line, and a server breaks a longer 7bit line wherever it likes, even
    # in the middle of an HTML tag.
    msg.attach(MIMEText(text_content, 'plain', 'utf-8'))
    if html_content:
        html_part = MIMEText(html_content, 'html', 'utf-8')
        icon = app_icon() if f'cid:{APP_ICON_CID}' in html_content else None
        if icon:
            related = MIMEMultipart('related')
            related.attach(html_part)
            image = MIMEImage(icon, 'png')
            image.add_header('Content-ID', f'<{APP_ICON_CID}>')
            image.add_header('Content-Disposition', 'inline', filename='app-icon.png')
            related.attach(image)
            msg.attach(related)
        else:
            msg.attach(html_part)
    return msg


class SmtpService:
    """Generic service for sending email notifications"""
    
    def __init__(self):
        self.host = settings.smtp_host
        self.port = settings.smtp_port
        self.use_tls = settings.smtp_use_tls
        self.use_ssl = settings.smtp_use_ssl
        self.user = settings.smtp_user
        self.password = settings.smtp_password
        self.relay_mode = settings.smtp_relay_mode
        self.from_address = settings.smtp_from or settings.smtp_user
    
    def is_configured(self) -> bool:
        """Check if SMTP is properly configured"""
        return settings.notification_smtp_configured
    
    def send_email(
        self,
        recipient: str,
        subject: str,
        text_content: str,
        html_content: Optional[str] = None
    ) -> bool:
        """
        Send email via SMTP
        
        Args:
            recipient: Email address to send to
            subject: Email subject
            text_content: Plain text content
            html_content: Optional HTML content
        
        Returns:
            True if email was sent successfully, False otherwise
        """
        if not self.is_configured():
            logger.warning("SMTP not configured, skipping email")
            return False
        
        recipients = parse_recipients(recipient)
        skipped = invalid_addresses(recipient)
        if skipped:
            logger.warning("Skipping invalid recipient address(es): %s", ", ".join(skipped))
        if not recipients:
            logger.warning("No recipient email provided, skipping email")
            return False

        try:
            # One message to every address; each one sees the others in To
            msg = build_message(self.from_address, ", ".join(recipients), subject, text_content, html_content)
            msg['Date'] = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S +0000')

            # Determine connection mode
            # Priority 1: Implicit SSL (if configured or using port 465)
            if self.use_ssl or self.port == 465:
                context = mail_tls_context(self.host, settings.smtp_verify_ssl, "SMTP_VERIFY_SSL")
                server = smtplib.SMTP_SSL(self.host, self.port, context=context)
            # Priority 2: STARTTLS (if configured)
            elif self.use_tls:
                context = mail_tls_context(self.host, settings.smtp_verify_ssl, "SMTP_VERIFY_SSL")
                server = smtplib.SMTP(self.host, self.port)
                server.starttls(context=context)
            # Priority 3: Plaintext
            else:
                server = smtplib.SMTP(self.host, self.port)
            
            # Skip login in relay mode
            if not self.relay_mode:
                server.login(self.user, self.password)
            
            server.sendmail(self.from_address, recipients, msg.as_string())
            server.quit()

            logger.info(f"Email sent successfully to {', '.join(recipients)}: {subject}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email: {certificate_error_hint(e, 'SMTP_VERIFY_SSL') or e}")
            return False


def get_notification_email(module_specific: Optional[str] = None) -> str:
    """
    Get email address for notifications with fallback logic
    
    Args:
        module_specific: Optional module-specific email override
    
    Returns:
        The address setting to use (module email or admin email); it may
        hold several addresses, see parse_recipients
    """
    if module_specific:
        return module_specific
    return settings.admin_email


def send_notification_email(
    recipient: str,
    subject: str,
    text_content: str,
    html_content: Optional[str] = None
) -> bool:
    """
    Convenience function to send notification email
    
    Args:
        recipient: Email address
        subject: Email subject
        text_content: Plain text content
        html_content: Optional HTML content
    
    Returns:
        True if sent successfully
    """
    service = SmtpService()
    
    if not service.is_configured():
        logger.info("SMTP not configured, skipping notification")
        return False
    
    return service.send_email(recipient, subject, text_content, html_content)