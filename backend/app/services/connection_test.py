"""
Connection testing utilities for SMTP and IMAP
Provides detailed logging for debugging
"""
import imaplib
import smtplib
import ssl
from typing import Dict, List
from ..config import settings, settings_snapshot
from .imap_folders import describe_setting, folder_targets, legacy_match, list_folders, parse_setting
from .mail_tls import mail_tls_context, certificate_error_hint, verify_mode


def _verify_label(verify) -> str:
    """How a *_VERIFY_SSL setting reads in the test log."""
    return {"false": "Off", "auto": "Automatic", "true": "On"}.get(verify_mode(verify), str(verify))


def test_smtp_connection() -> Dict:
    """Test SMTP connection and return detailed log"""
    logs = []
    success = False
    
    try:
        logs.append("Starting SMTP connection test...")
        logs.append(f"Host: {settings.smtp_host}")
        logs.append(f"Port: {settings.smtp_port}")
        logs.append(f"STARTTLS: {settings.smtp_use_tls}")
        logs.append(f"Implicit TLS setting: {settings.smtp_use_ssl}")
        logs.append(f"Verify TLS certificates: {_verify_label(settings.smtp_verify_ssl)}")
        logs.append(f"Send without authentication: {settings.smtp_relay_mode}")
        logs.append(f"SMTP username: {settings.smtp_user}")
        
        # Different validation for relay mode
        if settings.smtp_relay_mode:
            if not settings.smtp_host or not settings.smtp_from:
                logs.append("ERROR: Set SMTP host and From address in Settings > SMTP before testing the relay.")
                return {"success": False, "logs": logs}
        else:
            if not settings.smtp_host or not settings.smtp_user or not settings.smtp_password:
                logs.append("ERROR: Set SMTP host, SMTP username, and SMTP password in Settings > SMTP, then try again.")
                return {"success": False, "logs": logs}
        
        logs.append("Connecting to SMTP server...")
        
        # Same connection mode as SmtpService.send_email
        if settings.smtp_use_ssl or settings.smtp_port == 465:
            context = mail_tls_context(settings.smtp_host, settings.smtp_verify_ssl, "SMTP_VERIFY_SSL")
            server = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=10, context=context)
            logs.append("Connected using TLS")
        else:
            server = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10)
            logs.append("Connected")
            
            if settings.smtp_use_tls:
                logs.append("Starting TLS...")
                context = mail_tls_context(settings.smtp_host, settings.smtp_verify_ssl, "SMTP_VERIFY_SSL")
                server.starttls(context=context)
                logs.append("TLS established")
        
        # Skip login in relay mode
        if not settings.smtp_relay_mode:
            logs.append("Logging in...")
            server.login(settings.smtp_user, settings.smtp_password)
            logs.append("Login successful")
        else:
            logs.append("Relay mode - skipping authentication")
        
        from . import email_layout as e
        from .smtp_service import build_message, invalid_addresses, parse_recipients
        sender = settings.smtp_from or settings.smtp_user
        address_setting = settings.admin_email or settings.smtp_user
        skipped = invalid_addresses(address_setting)
        if skipped:
            logs.append(f"Skipping invalid address(es): {', '.join(skipped)}")
        recipients = parse_recipients(address_setting)
        if not recipients:
            logs.append("ERROR: No valid recipient address. Set Admin email in Settings > Notifications, then try again.")
            server.quit()
            return {"success": False, "logs": logs}
        recipient = ", ".join(recipients)
        logs.append(f"Sending test email to {recipient}...")
        body = "This is a test email from mailcow Logs Viewer.\n\nIf you received this, SMTP is working correctly."
        msg = build_message(sender, recipient, 'SMTP Test - mailcow Logs Viewer', body, e.render(
            title='SMTP works', topic='Test', tone='ok',
            intro='This is a test email. Alerts and the weekly summary can reach you.',
            blocks=[e.panel('Sent through', e.kv([
                ('Server', f"{settings.smtp_host}:{settings.smtp_port}"),
                ('From', sender),
                ('To', recipient),
            ]))],
            footer='The Test SMTP button sent this email.'))
        
        server.send_message(msg)
        logs.append("SMTP server accepted the test email")
        
        server.quit()
        logs.append("Connection closed")
        
        success = True
        logs.append("✓ SMTP test completed successfully")
        
    except ssl.SSLCertVerificationError as e:
        logs.append(f"✗ {certificate_error_hint(e, 'SMTP_VERIFY_SSL')}")
    except smtplib.SMTPAuthenticationError as e:
        logs.append(f"✗ Sign-in failed. Check the SMTP username and password. Details: {e}")
    except smtplib.SMTPException as e:
        logs.append(f"✗ SMTP test failed. Check Settings > SMTP and try again. Details: {e}")
    except Exception as e:
        logs.append(f"✗ Test failed. Check the application logs and try again. Details: {type(e).__name__}: {e}")
    
    return {
        "success": success,
        "logs": logs
    }


def _open_imap(current):
    """A logged-in IMAP connection with the given settings snapshot."""
    if current.dmarc_imap_use_ssl:
        context = mail_tls_context(current.dmarc_imap_host, current.dmarc_imap_verify_ssl, "DMARC_IMAP_VERIFY_SSL")
        connection = imaplib.IMAP4_SSL(current.dmarc_imap_host, current.dmarc_imap_port,
                                       ssl_context=context, timeout=30)
    else:
        connection = imaplib.IMAP4(current.dmarc_imap_host, current.dmarc_imap_port, timeout=30)
    try:
        connection.login(current.dmarc_imap_user, current.dmarc_imap_password)
    except Exception:
        _close(connection)
        raise
    return connection


def _close(connection):
    try:
        connection.logout()
    except Exception:
        pass


def test_imap_connection() -> Dict:
    """Test IMAP connection and return detailed log"""
    logs = []
    success = False
    # One snapshot: a save during the test cannot mix two accounts
    current = settings_snapshot()
    connection = None

    try:
        logs.append("Starting IMAP connection test...")
        logs.append(f"Host: {current.dmarc_imap_host}")
        logs.append(f"Port: {current.dmarc_imap_port}")
        logs.append(f"Use TLS: {current.dmarc_imap_use_ssl}")
        logs.append(f"Verify TLS certificates: {_verify_label(current.dmarc_imap_verify_ssl)}")
        logs.append(f"IMAP username: {current.dmarc_imap_user}")
        logs.append(f"Folders: {describe_setting(current.dmarc_imap_folder)}")

        if not current.dmarc_imap_host or not current.dmarc_imap_user or not current.dmarc_imap_password:
            logs.append("ERROR: Set IMAP host, IMAP username, and IMAP password in Settings > DMARC & TLS IMAP, then try again.")
            return {"success": False, "logs": logs}

        logs.append("Connecting to IMAP server...")
        logs.append("Logging in...")
        connection = _open_imap(current)
        logs.append("Login successful")

        targets, missing, empty, unreadable = folder_targets(connection, current.dmarc_imap_folder)
        problem = False
        for name in missing:
            logs.append(f"✗ Folder not found or not readable: {name}")
            problem = True
        if unreadable:
            logs.append(f"✗ {unreadable} folders could not be read from the server's folder list")
            problem = True
        for name in empty:
            logs.append(f"No folder to read under {name} yet")

        for target in targets:
            status, data = connection.select(target.select, readonly=True)
            if status == 'OK':
                logs.append(f"Folder {target.label}: {data[0].decode(errors='replace')} messages")
            else:
                logs.append(f"✗ Could not open folder {target.label}. Check Report folders in Settings > DMARC & TLS IMAP.")
                problem = True

        if not problem:
            success = True
            logs.append("✓ IMAP test completed successfully")

    except ssl.SSLCertVerificationError as e:
        logs.append(f"✗ {certificate_error_hint(e, 'DMARC_IMAP_VERIFY_SSL')}")
    except imaplib.IMAP4.error as e:
        logs.append(f"✗ IMAP test failed. Check the credentials and report folder, then try again. Details: {e}")
    except Exception as e:
        logs.append(f"✗ Test failed. Check the application logs and try again. Details: {type(e).__name__}: {e}")
    finally:
        if connection is not None:
            _close(connection)
            logs.append("Connection closed")

    return {
        "success": success,
        "logs": logs
    }


def list_imap_folders() -> Dict:
    """The stored IMAP account's folders, for choosing which ones to read.
    Uses the stored settings, never the form; never returns the password."""
    current = settings_snapshot()
    answer = {"ok": False, "host": None, "user": None, "folders": [], "legacy": None,
              "unreadable": 0, "error": None, "message": None}

    def failed(code, message):
        answer.update(error=code, message=message)
        return answer

    if not current.dmarc_imap_host or not current.dmarc_imap_user or not current.dmarc_imap_password:
        return failed("not_configured", "Set the IMAP host, username and password, and save them first.")
    connection = None
    try:
        connection = _open_imap(current)
        folders, unreadable = list_folders(connection)
    except ssl.SSLError as e:
        hint = certificate_error_hint(e, 'DMARC_IMAP_VERIFY_SSL') if isinstance(e, ssl.SSLCertVerificationError) else None
        return failed("tls", hint or "The secure connection to the IMAP server failed. Check the port and the TLS settings.")
    except imaplib.IMAP4.abort:
        return failed("unreachable", "The IMAP server closed the connection. Try again in a moment.")
    except imaplib.IMAP4.error:
        return failed("auth_failed", "The IMAP server refused the sign-in. Check the IMAP username and password.")
    except (OSError, TimeoutError):
        return failed("unreachable", "The IMAP server could not be reached. Check the host and the port.")
    except Exception as e:
        return failed("failed", f"The folders could not be listed: {type(e).__name__}.")
    finally:
        if connection is not None:
            _close(connection)

    entries, legacy = parse_setting(current.dmarc_imap_folder)
    answer.update(
        ok=True, host=current.dmarc_imap_host, user=current.dmarc_imap_user, unreadable=unreadable,
        folders=[{"name": f.name, "delimiter": f.delimiter, "selectable": f.selectable,
                  "can_have_children": f.can_have_children} for f in folders],
        legacy=None if entries is not None else {"value": legacy, "name": legacy_match(folders, legacy)},
    )
    return answer