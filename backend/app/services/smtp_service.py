"""
Global SMTP Service
Generic email notification service for all system modules
"""
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Optional

from ..config import settings
from .mail_tls import mail_tls_context, certificate_error_hint

logger = logging.getLogger(__name__)


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
        
        if not recipient:
            logger.warning("No recipient email provided, skipping email")
            return False
        
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.from_address
            msg['To'] = recipient
            msg['Date'] = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S +0000')
            
            part1 = MIMEText(text_content, 'plain')
            msg.attach(part1)
            
            if html_content:
                part2 = MIMEText(html_content, 'html')
                msg.attach(part2)
            
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
            
            server.sendmail(self.from_address, [recipient], msg.as_string())
            server.quit()
            
            logger.info(f"Email sent successfully to {recipient}: {subject}")
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
        Email address to use (module email or admin email)
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