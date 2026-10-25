"""
DMARC & TLS-RPT IMAP Service
Automatically fetches and processes DMARC and TLS-RPT reports from email inbox
"""
import logging
import imaplib
import email
import re
import threading
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple
from email.message import EmailMessage
from email.header import decode_header as decode_rfc2047

from ..config import settings
from .mail_tls import mail_tls_context, certificate_error_hint
from ..database import SessionLocal
from ..models import DMARCSync
from ..services.report_identity import (
    MAX_REPORT_ATTACHMENTS_PER_EMAIL,
    ReportBudget,
    ReportLimitError,
    ReportRejectedError,
    report_kind,
)
from ..services.report_store import ReportNotStored, prepare_report_file, store_report
from ..services.dmarc_notifications import send_dmarc_error_notification
from ..services.dmarc_cache import clear_dmarc_cache
from ..services.db_values import strip_nul

logger = logging.getLogger(__name__)

# Anyone can mail the report address, and a message is read whole into memory,
# with each attachment decoded, before any report limit applies. Larger
# messages are not downloaded. Real report emails are far below 1 MB; this
# still fits a report at the 10 MB compressed limit after base64 encoding.
MAX_REPORT_EMAIL_BYTES = 20 * 1024 * 1024
_MB = 1024 * 1024


def _decode_subject(raw_subject: str) -> str:
    """Decode an RFC 2047 encoded email subject to plain text.
    
    Handles encoded headers like:
    - =?iso-2022-jp?B?...?=  (Japanese)
    - =?utf-8?Q?...?=        (UTF-8 quoted-printable)
    - Plain ASCII subjects    (returned as-is)
    """
    if not raw_subject:
        return ''
    try:
        parts = decode_rfc2047(raw_subject)
        decoded_parts = []
        for content, charset in parts:
            if isinstance(content, bytes):
                decoded_parts.append(content.decode(charset or 'utf-8', errors='replace'))
            else:
                decoded_parts.append(content)
        return ' '.join(decoded_parts)
    except Exception:
        return raw_subject


# What one failure entry keeps of a header or an error text
_FAILURE_TEXT_CHARS = 1000
_DETAILS_NOT_STORED = "The details of this email could not be stored"


def _plain_text(value, limit: int = _FAILURE_TEXT_CHARS) -> Optional[str]:
    """A header or error text as plain text a JSON column can store.

    The sender chooses the headers and file names of a report email. A header
    with raw 8-bit bytes comes back as a Header object, a file name can
    decode to NUL, and either one used to fail the commit that stores the
    import's failure entries. None stays None."""
    if value is None:
        return None
    # str() of a Header shows bytes it cannot decode as U+FFFD; encoding with
    # 'replace' drops lone surrogates, which JSONB refuses like NUL
    text = str(value).encode('utf-8', 'replace').decode('utf-8')
    return strip_nul(text)[:limit]


def _record_counts(sync_record: DMARCSync, counts: Dict):
    for name, value in counts.items():
        setattr(sync_record, name, value)


def _header_text(msg, name: str) -> str:
    """A header of the email as bounded plain text, the subject decoded."""
    value = msg.get(name)
    if value is None:
        return 'unknown'
    text = _plain_text(value)
    return _plain_text(_decode_subject(text)) if name == 'subject' else text


class DMARCImapService:
    """Service to fetch DMARC reports from IMAP inbox"""
    
    def __init__(self):
        self.host = settings.dmarc_imap_host
        self.port = settings.dmarc_imap_port
        self.use_ssl = settings.dmarc_imap_use_ssl
        self.user = settings.dmarc_imap_user
        self.password = settings.dmarc_imap_password
        self.folder = settings.dmarc_imap_folder
        self.delete_after = settings.dmarc_imap_delete_after
        self.scan_all_unseen = settings.dmarc_imap_scan_all_unseen
        self.connection = None
        
    def connect(self) -> bool:
        """Connect to IMAP server"""
        try:
            if not self.host or not self.port:
                raise ValueError(f"IMAP server configuration incomplete: host={self.host}, port={self.port}")
            
            if self.use_ssl:
                context = mail_tls_context(self.host, settings.dmarc_imap_verify_ssl, "DMARC_IMAP_VERIFY_SSL")
                self.connection = imaplib.IMAP4_SSL(self.host, self.port, ssl_context=context, timeout=30)
            else:
                self.connection = imaplib.IMAP4(self.host, self.port, timeout=30)
            
            self.connection.login(self.user, self.password)
            logger.info(f"Successfully connected to IMAP server {self.host}:{self.port}")
            return True
            
        except ConnectionRefusedError as e:
            error_msg = f"Cannot connect to IMAP server {self.host}:{self.port} - Connection refused. Please check if the server is running and accessible."
            logger.error(error_msg)
            raise ConnectionError(error_msg) from e
        except Exception as e:
            hint = certificate_error_hint(e, "DMARC_IMAP_VERIFY_SSL")
            error_msg = f"Failed to connect to IMAP server {self.host}:{self.port}: {hint or e}"
            logger.error(error_msg)
            if hint:
                # The sync stores this message, so it has to name the setting to change
                raise ConnectionError(error_msg) from e
            raise
    
    def disconnect(self):
        """Disconnect from IMAP server"""
        if self.connection:
            try:
                self.connection.logout()
                logger.info("Disconnected from IMAP server")
            except Exception as e:
                logger.error(f"Error disconnecting from IMAP: {e}")
    
    def select_folder(self) -> bool:
        """Select the mailbox folder"""
        try:
            status, messages = self.connection.select(self.folder)
            if status != 'OK':
                logger.error(f"Failed to select folder {self.folder}")
                return False
            
            logger.info(f"Selected folder: {self.folder}")
            return True
            
        except Exception as e:
            logger.error(f"Error selecting folder: {e}")
            return False
    
    def search_report_emails(self) -> List[bytes]:
        """
        Search for DMARC and TLS-RPT report emails.
        
        Phase 1 (always): Search by known subject keywords (fast path).
        Phase 2 (when scan_all_unseen=True): Search all remaining UNSEEN
        emails to catch reports with non-English subjects.
        
        Returns list of email UIDs.
        """
        try:
            # Phase 1: Subject-based search (covers most DMARC/TLS-RPT providers)
            search_criteria = '(UNSEEN (OR (SUBJECT "Report Domain:") (OR (SUBJECT "DMARC") (OR (SUBJECT "Report-ID:") (OR (SUBJECT "TLS-RPT") (SUBJECT "TLS Report"))))))'
            
            status, messages = self.connection.uid('SEARCH', None, search_criteria)
            
            if status != 'OK':
                logger.error("Failed to search for report emails")
                return []
            
            email_ids = messages[0].split()
            logger.info(f"[Phase 1] Found {len(email_ids)} subject-matched DMARC/TLS-RPT emails")
            
            # Phase 2: Scan all remaining UNSEEN emails (opt-in)
            # This catches reports from providers that use non-English subjects
            if self.scan_all_unseen:
                subject_matched_set = set(email_ids)
                
                status2, messages2 = self.connection.uid('SEARCH', None, '(UNSEEN)')
                if status2 == 'OK':
                    all_unseen = messages2[0].split()
                    new_ids = [uid for uid in all_unseen if uid not in subject_matched_set]
                    if new_ids:
                        logger.info(f"[Phase 2] Scanning {len(new_ids)} additional unseen emails for DMARC attachments")
                        email_ids.extend(new_ids)
                    else:
                        logger.debug("[Phase 2] No additional unseen emails to scan")
            
            return email_ids
            
        except Exception as e:
            logger.error(f"Error searching for emails: {e}")
            return []
    
    def search_dmarc_emails(self) -> List[bytes]:
        """Alias for backward compatibility"""
        return self.search_report_emails()
    
    def is_bounce(self, msg: EmailMessage) -> bool:
        """
        Detect a delivery status notification (RFC 3464).

        The report mailbox is often also the address that mailcow sends its
        own DMARC reports from, so bounces of those reports land here. A bounce
        may carry the original outgoing report, which must not be imported.
        TLS-RPT mail is also multipart/report, but with report-type=tlsrpt.
        """
        if msg.get_content_type() == 'multipart/report':
            if str(msg.get_param('report-type', '')).lower() == 'delivery-status':
                return True
        return any(
            part.get_content_type() in ('message/delivery-status', 'message/global-delivery-status')
            for part in msg.walk()
        )

    def extract_attachments(self, msg: EmailMessage, include_json: bool = False) -> List[Tuple[str, bytes]]:
        """
        Extract compressed attachments from email
        
        Args:
            msg: Email message
            include_json: If True, also extract JSON files (for TLS-RPT)
        
        Returns list of (filename, content) tuples
        """
        attachments = []
        
        try:
            for part in msg.walk():
                # Try to get filename from Content-Disposition header
                filename = part.get_filename()
                
                # If no filename, try to get from Content-Type 'name' parameter
                if not filename:
                    content_type = part.get_content_type()
                    # Check if this is a potential attachment by content type
                    if content_type in ['application/gzip', 'application/x-gzip', 'application/zip', 
                                        'application/x-zip-compressed', 'text/xml', 'application/xml',
                                        'application/json', 'application/octet-stream']:
                        # Try to get name from content-type params
                        params = part.get_params()
                        if params:
                            for key, value in params:
                                if key.lower() == 'name':
                                    filename = value
                                    break
                
                if not filename:
                    continue
                
                filename_lower = filename.lower()
                
                # Support DMARC files: .xml.gz, .zip, .xml
                # Support TLS-RPT files: .json, .json.gz
                valid_extensions = ['.xml.gz', '.zip', '.xml']
                if include_json:
                    valid_extensions.extend(['.json', '.json.gz'])
                
                if not any(filename_lower.endswith(ext) for ext in valid_extensions):
                    continue
                
                content = part.get_payload(decode=True)
                if content:
                    attachments.append((filename, content))
                    logger.debug(f"Extracted attachment: {filename} ({len(content)} bytes)")
        
        except Exception as e:
            logger.error(f"Error extracting attachments: {e}")
        
        if not attachments:
            # Log all parts for debugging
            logger.debug(f"No attachments found. Email parts:")
            for i, part in enumerate(msg.walk()):
                ct = part.get_content_type()
                fn = part.get_filename()
                logger.debug(f"  Part {i}: type={ct}, filename={fn}")
        
        return attachments
    
    def _fetch_size(self, email_id: str) -> Optional[int]:
        """The message size the server reports (RFC822.SIZE), or None if it gives none."""
        status, data = self.connection.uid('FETCH', email_id, '(RFC822.SIZE)')
        if status != 'OK':
            return None
        for item in data or []:
            line = item[0] if isinstance(item, tuple) else item
            match = re.search(rb'RFC822\.SIZE (\d+)', line) if isinstance(line, bytes) else None
            if match:
                return int(match.group(1))
        return None

    def _fetch_headers(self, email_id: str) -> EmailMessage:
        """Message-ID and Subject only, without downloading the message or marking it read."""
        status, data = self.connection.uid('FETCH', email_id, '(BODY.PEEK[HEADER.FIELDS (MESSAGE-ID SUBJECT)])')
        for item in (data if status == 'OK' else None) or []:
            if isinstance(item, tuple) and isinstance(item[1], bytes):
                return email.message_from_bytes(item[1])
        return email.message_from_bytes(b'')

    def process_email(self, email_id: str, db: SessionLocal) -> Dict:
        """
        Process a single DMARC or TLS-RPT email
        
        Returns dict with:
        - success: bool
        - reports_created: int
        - reports_duplicate: int
        - error: str or None
        - report_type: 'dmarc', 'tls-rpt' or 'mixed'
        - skipped: why the email is not a report (bounce or no report attached), or None
        - keep: True when a report in it shares its report ID with another stored
          report: the email stays in the mailbox even when it was imported
        """
        result = {
            'success': False,
            'reports_created': 0,
            'reports_duplicate': 0,
            'error': None,
            'message_id': None,
            'subject': None,
            'report_type': None,
            'skipped': None,
            'keep': False
        }
        
        try:
            size = self._fetch_size(email_id)
            if size is not None and size > MAX_REPORT_EMAIL_BYTES:
                headers = self._fetch_headers(email_id)
                result['message_id'] = _header_text(headers, 'message-id')
                result['subject'] = _header_text(headers, 'subject')
                result['error'] = (f"The email is {size / _MB:.0f} MB, larger than the "
                                   f"{MAX_REPORT_EMAIL_BYTES // _MB} MB a report email may have, "
                                   f"so it was not downloaded")
                return result

            # Fetch email (email_id is already a string)
            status, msg_data = self.connection.uid('FETCH', email_id, '(RFC822)')
            
            if status != 'OK':
                result['error'] = f"Failed to fetch email {email_id}"
                return result
            
            # Parse email
            msg = email.message_from_bytes(msg_data[0][1])
            result['message_id'] = _header_text(msg, 'message-id')
            result['subject'] = _header_text(msg, 'subject')

            if self.is_bounce(msg):
                result['skipped'] = 'bounce'
                return result

            return self._process_reports(msg, db, result)

        except Exception as e:
            logger.error(f"Error processing email {email_id}: {e}")
            db.rollback()
            result['error'] = str(e)
            return result

    def report_attachments(self, msg: EmailMessage) -> List[Tuple[str, bytes, str]]:
        """Every report file of the email as (filename, content, 'dmarc' or 'tls-rpt').

        Each file is classified on its own, so an email that carries a DMARC and
        a TLS-RPT report has both read before it can count as imported.
        """
        return [(filename, content, report_kind(filename, content))
                for filename, content in self.extract_attachments(msg, include_json=True)]

    def _process_reports(self, msg: EmailMessage, db: SessionLocal, result: Dict) -> Dict:
        """Import the reports of one email, all or nothing for the limits.

        The email counts as imported (and may be deleted) only when every report
        in it was stored or was already stored with the same content. Reports
        are committed here, before the caller marks or deletes the email.
        """
        attachments = self.report_attachments(msg)
        if not attachments:
            result['skipped'] = 'no report attached'
            return result
        kinds = {kind for _, _, kind in attachments}
        result['report_type'] = kinds.pop() if len(kinds) == 1 else 'mixed'

        if len(attachments) > MAX_REPORT_ATTACHMENTS_PER_EMAIL:
            result['error'] = (f"The email has {len(attachments)} report files, more than the "
                               f"{MAX_REPORT_ATTACHMENTS_PER_EMAIL} allowed, so nothing from it was imported.")
            return result

        # Read every report before storing any, so an email over a limit stores nothing
        budget = ReportBudget()
        prepared = []
        attachment_errors = []
        for filename, content, kind in attachments:
            try:
                report = prepare_report_file(kind, content, filename)
                if report is not None:
                    budget.add(report.items, report.size)
            except ReportLimitError as e:
                result['error'] = f"{filename}: {e} Nothing from this email was imported."
                return result
            except ReportRejectedError as e:
                attachment_errors.append(f"{filename}: {e}")
                continue
            if report is None:
                attachment_errors.append(f"Failed to parse: {filename}")
                logger.warning(f"Failed to parse attachment: {filename}")
                continue
            prepared.append((filename, report))

        created = duplicate = 0
        keep = False
        try:
            # One order for the report ID locks, whatever the order of the files
            for filename, report in sorted(prepared, key=lambda item: (item[1].kind, item[1].report_id)):
                try:
                    status, _ = store_report(db, report)
                except ReportNotStored as e:
                    # The report's own savepoint is rolled back; the others stay
                    attachment_errors.append(f"Error processing {filename}: {e}")
                    logger.error(f"Error processing {filename}: {e}")
                    continue
                if status == 'duplicate':
                    duplicate += 1
                else:
                    created += 1
                    # Another report has its report ID: keep the email for a look
                    keep = keep or status == 'conflict'
            db.commit()
        except Exception as e:
            db.rollback()
            logger.error(f"Could not save the reports of the email: {e}")
            result['error'] = f"The reports could not be saved: {e}"
            return result

        result['reports_created'] = created
        result['reports_duplicate'] = duplicate
        result['keep'] = keep
        if attachment_errors:
            result['error'] = "; ".join(attachment_errors)
        else:
            result['success'] = True
        return result
    
    def mark_as_processed(self, email_id: str):
        """Mark email as processed (flag or move)"""
        try:
            # Add a flag to mark as processed
            self.connection.uid('STORE', email_id, '+FLAGS', '\\Seen')
            logger.debug(f"Marked email {email_id} as seen")
            
        except Exception as e:
            logger.error(f"Error marking email as processed: {e}")
    
    def delete_email(self, email_id: str):
        """Delete email from server"""
        try:
            self.connection.uid('STORE', email_id, '+FLAGS', '\\Deleted')
            self.connection.expunge()
            logger.debug(f"Deleted email {email_id}")
            
        except Exception as e:
            logger.error(f"Error deleting email: {e}")
    
    def sync_reports(self, sync_type: str = 'auto') -> Dict:
        """
        Main sync function with batch processing

        Processes emails in batches to prevent memory issues with large mailboxes.
        After each batch, emails are deleted/marked and the search is re-run
        to get the next batch of unprocessed emails.

        Each email's counts and failure entry are committed before the email
        is marked or deleted, so a failure is stored before its email leaves
        the import. The failures are reported once, also when the import
        itself fails; the result then says 'notified'.

        Returns statistics about the sync operation
        """
        sync_record = DMARCSync(
            sync_type=sync_type,
            started_at=datetime.now(timezone.utc),
            status='running'
        )

        db = SessionLocal()
        batch_size = settings.dmarc_imap_batch_size
        # Kept here, not only on the record: a rollback resets the record
        counts = {'emails_processed': 0, 'reports_created': 0,
                  'reports_duplicate': 0, 'reports_failed': 0}
        failed_emails = []
        notified = False

        try:
            db.add(sync_record)
            db.commit()
            db.refresh(sync_record)

            # Connect to IMAP
            self.connect()

            # Select folder
            if not self.select_folder():
                raise Exception(f"Failed to select folder {self.folder}")

            # Initial search to count total emails
            all_email_ids = self.search_dmarc_emails()
            total_emails = len(all_email_ids)
            sync_record.emails_found = total_emails
            db.commit()

            if not all_email_ids:
                logger.info("No DMARC emails found")
                sync_record.status = 'success'
                sync_record.completed_at = datetime.now(timezone.utc)
                db.commit()
                return self._build_result(sync_record)

            logger.info(f"Found {total_emails} DMARC emails, processing in batches of {batch_size}")

            # Process in batches
            batch_number = 0

            while True:
                batch_number += 1

                # Re-search to get current unprocessed emails (since we delete/mark after each batch)
                email_ids = self.search_dmarc_emails()

                if not email_ids:
                    logger.info(f"Batch {batch_number}: No more emails to process")
                    break

                # Take only batch_size emails
                batch_emails = email_ids[:batch_size]
                logger.info(f"Batch {batch_number}: Processing {len(batch_emails)} emails (remaining: {len(email_ids)})")

                for email_id in batch_emails:
                    email_id = email_id.decode() if isinstance(email_id, bytes) else email_id
                    result = self.process_email(email_id, db)
                    counts['emails_processed'] += 1
                    # Committed reports count even when another report of the email failed
                    counts['reports_created'] += result['reports_created']
                    counts['reports_duplicate'] += result['reports_duplicate']

                    if result['skipped']:
                        # Not a report (e.g. a bounce): not a failure, and never deleted
                        logger.info(f"Skipped email {email_id} ({result['skipped']}): {result['subject']}")
                        self._save_progress(db, sync_record, counts, failed_emails)
                        self.mark_as_processed(email_id)
                    elif result['success']:
                        # Every report of the email is stored: delete or mark as processed
                        self._save_progress(db, sync_record, counts, failed_emails)
                        if self.delete_after and not result.get('keep'):
                            self.delete_email(email_id)
                        else:
                            self.mark_as_processed(email_id)
                    else:
                        counts['reports_failed'] += 1
                        error_msg = result.get('error') or 'Unknown error'
                        logger.warning(f"Failed to process email {email_id}: {error_msg}")

                        failed_emails.append({
                            'email_id': _plain_text(email_id),
                            'message_id': _plain_text(result['message_id']),
                            'subject': _plain_text(result['subject']),
                            'error': _plain_text(error_msg)
                        })
                        self._save_progress(db, sync_record, counts, failed_emails)
                        # Kept in the mailbox, marked so it is not processed again
                        self.mark_as_processed(email_id)

                # Log batch progress
                logger.info(f"Batch {batch_number} complete: "
                           f"{counts['emails_processed']}/{total_emails} processed, "
                           f"{counts['reports_created']} created, "
                           f"{counts['reports_failed']} failed")

            # Update sync record
            _record_counts(sync_record, counts)
            sync_record.status = 'success'
            sync_record.completed_at = datetime.now(timezone.utc)
            sync_record.failed_emails = list(failed_emails) or None

            if failed_emails:
                sync_record.error_message = f"{len(failed_emails)} emails failed to process"

            db.commit()

            logger.info(f"DMARC sync completed: {counts['reports_created']} created, "
                       f"{counts['reports_duplicate']} duplicates, "
                       f"{counts['reports_failed']} failed")

            # Clear cache if any reports were created
            if counts['reports_created'] > 0:
                clear_dmarc_cache(db)

            notified = self._notify_failures(failed_emails, sync_record.id)
            return self._build_result(sync_record)

        except Exception as e:
            logger.error(f"DMARC sync failed: {e}")
            # A failed statement leaves the session unusable until rolled back
            db.rollback()
            try:
                _record_counts(sync_record, counts)
                sync_record.status = 'error'
                sync_record.completed_at = datetime.now(timezone.utc)
                sync_record.error_message = _plain_text(e)
                sync_record.failed_emails = list(failed_emails) or None
                db.commit()
                result = self._build_result(sync_record)
            except Exception as record_error:
                logger.error(f"Could not record the failed DMARC sync: {record_error}")
                db.rollback()
                result = {'sync_id': None, 'sync_type': sync_type, 'status': 'error',
                          'error_message': _plain_text(e), 'failed_emails': list(failed_emails) or None,
                          **counts}

            # Return error result instead of raising exception
            # This allows the scheduler to handle it gracefully
            if not notified:
                result['notified'] = self._notify_failures(failed_emails, result.get('sync_id'))
            return result

        finally:
            self.disconnect()
            db.close()

    def _save_progress(self, db, sync_record: DMARCSync, counts: Dict, failed_emails: List[Dict]):
        """Commit the counts and failure entries so far. When the newest
        failure entry still cannot be stored, it is replaced with one that
        keeps only the email number, so the email can be marked and the
        import does not stop on it in every run."""
        _record_counts(sync_record, counts)
        # A new list: the session does not see a change inside a JSON value
        sync_record.failed_emails = list(failed_emails) or None
        try:
            db.commit()
        except Exception as error:
            if not failed_emails:
                raise
            logger.warning(f"Could not store the failure entry of email "
                           f"{failed_emails[-1]['email_id']} ({type(error).__name__})")
            db.rollback()
            failed_emails[-1] = {'email_id': failed_emails[-1]['email_id'], 'message_id': None,
                                 'subject': None, 'error': _DETAILS_NOT_STORED}
            _record_counts(sync_record, counts)
            sync_record.failed_emails = list(failed_emails)
            db.commit()

    def _notify_failures(self, failed_emails: List[Dict], sync_id) -> bool:
        """Report the failures; the notification goes to the channels even
        without SMTP. True when there were failures to report."""
        if not failed_emails:
            return False
        logger.info(f"Sending error notification for {len(failed_emails)} failed emails")
        try:
            if send_dmarc_error_notification(failed_emails, sync_id):
                logger.info("Error notification sent successfully")
        except Exception as email_error:
            logger.error(f"Failed to send error notification: {email_error}")
        return True

    def _build_result(self, sync_record: DMARCSync) -> Dict:
        """Build result dictionary from sync record"""
        return {
            'sync_id': sync_record.id,
            'sync_type': sync_record.sync_type,
            'status': sync_record.status,
            'started_at': sync_record.started_at.strftime('%Y-%m-%dT%H:%M:%SZ') if sync_record.started_at else None,
            'completed_at': sync_record.completed_at.strftime('%Y-%m-%dT%H:%M:%SZ') if sync_record.completed_at else None,
            'emails_found': sync_record.emails_found,
            'emails_processed': sync_record.emails_processed,
            'reports_created': sync_record.reports_created,
            'reports_duplicate': sync_record.reports_duplicate,
            'reports_failed': sync_record.reports_failed,
            'error_message': sync_record.error_message,
            'failed_emails': sync_record.failed_emails
        }


# One import at a time: the scheduled run, Fetch reports and Status > Run now
# all start it, and two at once would read the same mailbox. The app runs in
# one process, so this lock sees every import.
_sync_lock = threading.Lock()


def is_sync_running() -> bool:
    """True while an IMAP import runs."""
    return _sync_lock.locked()


def _fail_interrupted_syncs():
    """Mark imports still 'running' as failed. Called under the lock, so
    none of them runs: the app stopped during them. Best effort."""
    try:
        with SessionLocal() as db:
            db.query(DMARCSync).filter(DMARCSync.status == 'running').update({
                "status": "failed",
                "error_message": "Interrupted: the app stopped during the import"
            })
            db.commit()
    except Exception as e:
        logger.warning(f"Could not mark interrupted DMARC imports as failed: {e}")


def sync_dmarc_reports_from_imap(sync_type: str = 'auto') -> Dict:
    """
    Convenience function to sync DMARC reports
    Can be called from scheduler or API endpoint
    """
    if not settings.dmarc_imap_enabled:
        logger.info("DMARC IMAP sync is disabled")
        return {
            'status': 'disabled',
            'message': 'DMARC IMAP sync is not enabled'
        }

    if not _sync_lock.acquire(blocking=False):
        logger.info("DMARC IMAP import already running, not starting another")
        return {
            'status': 'already_running',
            'message': 'Reports are already being fetched'
        }
    try:
        _fail_interrupted_syncs()
        service = DMARCImapService()
        return service.sync_reports(sync_type=sync_type)
    finally:
        _sync_lock.release()