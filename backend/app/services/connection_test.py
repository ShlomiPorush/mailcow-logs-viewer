"""
Connection testing utilities for SMTP and IMAP
Provides detailed logging for debugging
"""
import imaplib
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List
from ..config import settings


def test_smtp_connection() -> Dict:
    """Test SMTP connection and return detailed log"""
    logs = []
    success = False
    
    try:
        logs.append("Starting SMTP connection test...")
        logs.append(f"Host: {settings.smtp_host}")
        logs.append(f"Port: {settings.smtp_port}")
        logs.append(f"Use TLS: {settings.smtp_use_tls}")
        logs.append(f"Relay Mode: {settings.smtp_relay_mode}")
        logs.append(f"User: {settings.smtp_user}")
        
        # Different validation for relay mode
        if settings.smtp_relay_mode:
            if not settings.smtp_host or not settings.smtp_from:
                logs.append("ERROR: SMTP relay mode requires host and from address")
                return {"success": False, "logs": logs}
        else:
            if not settings.smtp_host or not settings.smtp_user or not settings.smtp_password:
                logs.append("ERROR: SMTP not fully configured")
                return {"success": False, "logs": logs}
        
        logs.append("Connecting to SMTP server...")
        
        if settings.smtp_port == 465:
            server = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=10)
            logs.append("Connected using SSL")
        else:
            server = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10)
            logs.append("Connected")
            
            if settings.smtp_use_tls:
                logs.append("Starting TLS...")
                server.starttls()
                logs.append("TLS established")
        
        # Skip login in relay mode
        if not settings.smtp_relay_mode:
            logs.append("Logging in...")
            server.login(settings.smtp_user, settings.smtp_password)
            logs.append("Login successful")
        else:
            logs.append("Relay mode - skipping authentication")
        
        logs.append("Sending test email...")
        msg = MIMEMultipart()
        msg['From'] = settings.smtp_from or settings.smtp_user
        msg['To'] = settings.admin_email or settings.smtp_user
        msg['Subject'] = 'SMTP Test - Mailcow Logs Viewer'
        
        body = "This is a test email from Mailcow Logs Viewer.\n\nIf you received this, SMTP is working correctly."
        msg.attach(MIMEText(body, 'plain'))
        
        server.send_message(msg)
        logs.append("Test email sent successfully")
        
        server.quit()
        logs.append("Connection closed")
        
        success = True
        logs.append("✓ SMTP test completed successfully")
        
    except smtplib.SMTPAuthenticationError as e:
        logs.append(f"✗ Authentication failed: {e}")
    except smtplib.SMTPException as e:
        logs.append(f"✗ SMTP error: {e}")
    except Exception as e:
        logs.append(f"✗ Unexpected error: {type(e).__name__}: {e}")
    
    return {
        "success": success,
        "logs": logs
    }


def test_imap_connection() -> Dict:
    """Test IMAP connection and return detailed log"""
    logs = []
    success = False
    
    try:
        logs.append("Starting IMAP connection test...")
        logs.append(f"Host: {settings.dmarc_imap_host}")
        logs.append(f"Port: {settings.dmarc_imap_port}")
        logs.append(f"Use SSL: {settings.dmarc_imap_use_ssl}")
        logs.append(f"User: {settings.dmarc_imap_user}")
        logs.append(f"Folder: {settings.dmarc_imap_folder}")
        
        if not settings.dmarc_imap_host or not settings.dmarc_imap_user or not settings.dmarc_imap_password:
            logs.append("ERROR: IMAP not fully configured")
            return {"success": False, "logs": logs}
        
        logs.append("Connecting to IMAP server...")
        
        if settings.dmarc_imap_use_ssl:
            connection = imaplib.IMAP4_SSL(settings.dmarc_imap_host, settings.dmarc_imap_port, timeout=30)
            logs.append("Connected using SSL")
        else:
            connection = imaplib.IMAP4(settings.dmarc_imap_host, settings.dmarc_imap_port, timeout=30)
            logs.append("Connected without SSL")
        
        logs.append("Logging in...")
        connection.login(settings.dmarc_imap_user, settings.dmarc_imap_password)
        logs.append("Login successful")
        
        logs.append(f"Listing mailboxes...")
        status, mailboxes = connection.list()
        if status == 'OK':
            logs.append(f"Found {len(mailboxes)} mailboxes:")
            for mb in mailboxes[:5]:
                logs.append(f"  - {mb.decode()}")
            if len(mailboxes) > 5:
                logs.append(f"  ... and {len(mailboxes) - 5} more")
        
        logs.append(f"Selecting folder: {settings.dmarc_imap_folder}")
        status, data = connection.select(settings.dmarc_imap_folder, readonly=True)
        if status == 'OK':
            logs.append(f"Folder selected: {data[0].decode()} messages")
        else:
            logs.append(f"✗ Failed to select folder: {data}")
            return {"success": False, "logs": logs}
        
        logs.append("Searching for emails...")
        status, messages = connection.search(None, 'ALL')
        if status == 'OK':
            email_ids = messages[0].split()
            logs.append(f"Found {len(email_ids)} emails in folder")
        
        connection.logout()
        logs.append("Connection closed")
        
        success = True
        logs.append("✓ IMAP test completed successfully")
        
    except imaplib.IMAP4.error as e:
        logs.append(f"✗ IMAP error: {e}")
    except Exception as e:
        logs.append(f"✗ Unexpected error: {type(e).__name__}: {e}")
    
    return {
        "success": success,
        "logs": logs
    }