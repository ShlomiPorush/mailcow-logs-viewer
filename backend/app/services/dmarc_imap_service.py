import logging
import imaplib
import email
import re
import threading
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple
from email.message import EmailMessage
from email.header import decode_header as decode_rfc2047

from ..config import settings, settings_snapshot
from .imap_folders import folder_targets
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
from ..services.db_values import is_row_error, strip_nul

logger = logging.getLogger(__name__)

MAX_REPORT_EMAIL_BYTES = 20 * 1024 * 1024
_MB = 1024 * 1024


def _decode_subject(raw_subject: str) -> str:
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


_FAILURE_TEXT_CHARS = 1000
_DETAILS_NOT_STORED = "The details of this email could not be stored"


def _plain_text(value, limit: int = _FAILURE_TEXT_CHARS) -> Optional[str]:
    if value is None:
        return None
    text = str(value).encode('utf-8', 'replace').decode('utf-8')
    return strip_nul(text)[:limit]


def _is_value_error(error: Exception) -> bool:
    return is_row_error(error) or isinstance(getattr(error, 'orig', None), (TypeError, ValueError))


def _record_counts(sync_record: DMARCSync, counts: Dict):
    for name, value in counts.items():
        setattr(sync_record, name, value)


def _header_text(msg, name: str) -> str:
    value = msg.get(name)
    if value is None:
        return 'unknown'
    text = _plain_text(value)
    return _plain_text(_decode_subject(text)) if name == 'subject' else text


class DMARCImapService:
    
    def __init__(self):
        current = settings_snapshot()
        self.host = current.dmarc_imap_host
        self.port = current.dmarc_imap_port
        self.use_ssl = current.dmarc_imap_use_ssl
        self.verify_ssl = current.dmarc_imap_verify_ssl
        self.user = current.dmarc_imap_user
        self.password = current.dmarc_imap_password
        self.folder = current.dmarc_imap_folder
        self.delete_after = current.dmarc_imap_delete_after
        self.scan_all_unseen = current.dmarc_imap_scan_all_unseen
        self.batch_size = current.dmarc_imap_batch_size
        self.connection = None
        self.uidplus = False

    def connect(self) -> bool:
        try:
            if not self.host or not self.port:
                raise ValueError(f"IMAP server configuration incomplete: host={self.host}, port={self.port}")
            
            if self.use_ssl:
                context = mail_tls_context(self.host, self.verify_ssl, "DMARC_IMAP_VERIFY_SSL")
                self.connection = imaplib.IMAP4_SSL(self.host, self.port, ssl_context=context, timeout=30)
            else:
                self.connection = imaplib.IMAP4(self.host, self.port, timeout=30)

            self.connection.login(self.user, self.password)
            status, data = self.connection.capability()
            self.uidplus = status == 'OK' and bool(data) and b'UIDPLUS' in (data[0] or b'').upper().split()
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
                raise ConnectionError(error_msg) from e
            raise
    
    def disconnect(self):
        if self.connection:
            try:
                self.connection.logout()
                logger.info("Disconnected from IMAP server")
            except Exception as e:
                logger.error(f"Error disconnecting from IMAP: {e}")
    
    def select_folder(self, folder: Optional[str] = None) -> bool:
        folder = self.folder if folder is None else folder
        try:
            status, messages = self.connection.select(folder)
            if status != 'OK':
                logger.error(f"Failed to select folder {folder}")
                return False

            logger.info(f"Selected folder: {folder}")
            return True

        except imaplib.IMAP4.readonly:
            logger.error(f"Folder {folder} is read-only")
            return False
        except imaplib.IMAP4.abort:
            raise
        except Exception as e:
            logger.error(f"Error selecting folder: {e}")
            return False
    
    def search_report_emails(self) -> List[bytes]:
        search_criteria = '(UNSEEN (OR (SUBJECT "Report Domain:") (OR (SUBJECT "DMARC") (OR (SUBJECT "Report-ID:") (OR (SUBJECT "TLS-RPT") (SUBJECT "TLS Report"))))))'

        status, messages = self.connection.uid('SEARCH', None, search_criteria)

        if status != 'OK':
            raise RuntimeError("The IMAP server refused the search for report emails")

        email_ids = (messages[0] or b'').split()
        logger.info(f"[Phase 1] Found {len(email_ids)} subject-matched DMARC/TLS-RPT emails")

        if self.scan_all_unseen:
            subject_matched_set = set(email_ids)

            status2, messages2 = self.connection.uid('SEARCH', None, '(UNSEEN)')
            if status2 != 'OK':
                raise RuntimeError("The IMAP server refused the search for unread emails")
            all_unseen = (messages2[0] or b'').split()
            new_ids = [uid for uid in all_unseen if uid not in subject_matched_set]
            if new_ids:
                logger.info(f"[Phase 2] Scanning {len(new_ids)} additional unseen emails for DMARC attachments")
                email_ids.extend(new_ids)
            else:
                logger.debug("[Phase 2] No additional unseen emails to scan")

        return email_ids
    
    def search_dmarc_emails(self) -> List[bytes]:
        return self.search_report_emails()
    
    def is_bounce(self, msg: EmailMessage) -> bool:
        if msg.get_content_type() == 'multipart/report':
            if str(msg.get_param('report-type', '')).lower() == 'delivery-status':
                return True
        return any(
            part.get_content_type() in ('message/delivery-status', 'message/global-delivery-status')
            for part in msg.walk()
        )

    def extract_attachments(self, msg: EmailMessage, include_json: bool = False) -> List[Tuple[str, bytes]]:
        attachments = []
        
        try:
            for part in msg.walk():
                filename = part.get_filename()
                
                if not filename:
                    content_type = part.get_content_type()
                    if content_type in ['application/gzip', 'application/x-gzip', 'application/zip', 
                                        'application/x-zip-compressed', 'text/xml', 'application/xml',
                                        'application/json', 'application/octet-stream']:
                        params = part.get_params()
                        if params:
                            for key, value in params:
                                if key.lower() == 'name':
                                    filename = value
                                    break
                
                if not filename:
                    continue
                
                filename_lower = filename.lower()
                
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
            logger.debug(f"No attachments found. Email parts:")
            for i, part in enumerate(msg.walk()):
                ct = part.get_content_type()
                fn = part.get_filename()
                logger.debug(f"  Part {i}: type={ct}, filename={fn}")
        
        return attachments
    
    def _fetch_size(self, email_id: str) -> Optional[int]:
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
        status, data = self.connection.uid('FETCH', email_id, '(BODY.PEEK[HEADER.FIELDS (MESSAGE-ID SUBJECT)])')
        for item in (data if status == 'OK' else None) or []:
            if isinstance(item, tuple) and isinstance(item[1], bytes):
                return email.message_from_bytes(item[1])
        return email.message_from_bytes(b'')

    def process_email(self, email_id: str, db: SessionLocal) -> Dict:
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

            status, msg_data = self.connection.uid('FETCH', email_id, '(BODY.PEEK[])')
            
            if status != 'OK':
                result['error'] = f"Failed to fetch email {email_id}"
                return result
            
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
        return [(filename, content, report_kind(filename, content))
                for filename, content in self.extract_attachments(msg, include_json=True)]

    def _process_reports(self, msg: EmailMessage, db: SessionLocal, result: Dict) -> Dict:
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
            # Unsorted, two imports that lock the same report IDs in another order can deadlock
            for filename, report in sorted(prepared, key=lambda item: (item[1].kind, item[1].report_id)):
                try:
                    status, _ = store_report(db, report)
                except ReportNotStored as e:
                    attachment_errors.append(f"Error processing {filename}: {e}")
                    logger.error(f"Error processing {filename}: {e}")
                    continue
                if status == 'duplicate':
                    duplicate += 1
                else:
                    created += 1
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
    
    def _store(self, email_id: str, flag: str):
        status, _ = self.connection.uid('STORE', email_id, '+FLAGS', flag)
        if status != 'OK':
            raise RuntimeError(f"The IMAP server refused to set {flag} on email {email_id}")

    def mark_as_processed(self, email_id: str):
        self._store(email_id, '\\Seen')
        logger.debug(f"Marked email {email_id} as seen")

    def delete_email(self, email_id: str):
        self._store(email_id, '\\Deleted')
        if self.uidplus:
            status, _ = self.connection.uid('EXPUNGE', email_id)
            if status != 'OK':
                raise RuntimeError(f"The IMAP server refused to remove email {email_id}")
            logger.debug(f"Deleted email {email_id}")
        else:
            self.mark_as_processed(email_id)
            logger.debug(f"Marked email {email_id} as deleted; the server cannot remove single emails")
    
    def sync_reports(self, sync_type: str = 'auto') -> Dict:
        sync_record = DMARCSync(
            sync_type=sync_type,
            started_at=datetime.now(timezone.utc),
            status='running'
        )

        db = SessionLocal()
        batch_size = self.batch_size
        counts = {'emails_found': 0, 'emails_processed': 0, 'reports_created': 0,
                  'reports_duplicate': 0, 'reports_failed': 0}
        failed_emails = []
        notified = False

        try:
            db.add(sync_record)
            db.commit()
            db.refresh(sync_record)

            self.connect()
            if self.delete_after and not self.uidplus:
                logger.info("The IMAP server cannot remove single emails (no UIDPLUS): imported "
                            "emails are marked as deleted and read, for a mail client to remove")

            targets, missing, empty, unreadable = folder_targets(self.connection, self.folder)
            problems = []
            if missing:
                problems.append(f"Folder not found or not readable: {', '.join(missing)}")
            if unreadable:
                problems.append(f"{unreadable} folders could not be read from the server's folder list")
            for name in empty:
                logger.info(f"No folder to read under {name} yet")

            for target in targets:
                if not self.select_folder(target.select):
                    problems.append(f"Failed to select folder {target.label}")
                    continue
                self._sync_folder(db, sync_record, target.label, batch_size, counts, failed_emails)

            _record_counts(sync_record, counts)
            sync_record.status = 'error' if problems else 'success'
            sync_record.completed_at = datetime.now(timezone.utc)
            sync_record.failed_emails = list(failed_emails) or None

            messages = list(problems)
            if failed_emails:
                messages.append(f"{len(failed_emails)} emails failed to process")
            if messages:
                sync_record.error_message = _plain_text('; '.join(messages))

            db.commit()

            logger.info(f"DMARC sync completed: {counts['reports_created']} created, "
                       f"{counts['reports_duplicate']} duplicates, "
                       f"{counts['reports_failed']} failed")

            if counts['reports_created'] > 0:
                clear_dmarc_cache(db)

            notified = self._notify_failures(failed_emails, sync_record.id)
            return self._build_result(sync_record)

        except Exception as e:
            logger.error(f"DMARC sync failed: {e}")
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

            if counts['reports_created'] > 0:
                try:
                    clear_dmarc_cache(db)
                except Exception as cache_error:
                    logger.error(f"Could not clear the DMARC cache: {cache_error}")

            if not notified:
                notified = self._notify_failures(failed_emails, result.get('sync_id'))
            result['notified'] = notified
            return result

        finally:
            self.disconnect()
            db.close()

    def _sync_folder(self, db, sync_record: DMARCSync, folder: str, batch_size: int,
                     counts: Dict, failed_emails: List[Dict]):
        found = len(self.search_dmarc_emails())
        counts['emails_found'] += found
        _record_counts(sync_record, counts)
        db.commit()
        if not found:
            logger.info(f"No DMARC emails found in {folder}")
            return

        logger.info(f"Found {found} DMARC emails in {folder}, processing in batches of {batch_size}")
        handled = set()
        batch_number = 0

        while True:
            batch_number += 1

            listed = self.search_dmarc_emails()
            email_ids = [uid for uid in listed if uid not in handled]

            if not email_ids:
                if listed:
                    raise RuntimeError(f"The server kept showing emails in {folder} that were "
                                       f"already handled as unread")
                logger.info(f"Batch {batch_number}: No more emails to process in {folder}")
                break

            batch_emails = email_ids[:batch_size]
            logger.info(f"Batch {batch_number}: Processing {len(batch_emails)} emails (remaining: {len(email_ids)})")

            for raw_id in batch_emails:
                handled.add(raw_id)
                email_id = raw_id.decode() if isinstance(raw_id, bytes) else raw_id
                result = self.process_email(email_id, db)
                counts['emails_processed'] += 1
                counts['reports_created'] += result['reports_created']
                counts['reports_duplicate'] += result['reports_duplicate']

                if result['skipped']:
                    logger.info(f"Skipped email {email_id} ({result['skipped']}): {result['subject']}")
                    self._save_progress(db, sync_record, counts, failed_emails)
                    self.mark_as_processed(email_id)
                elif result['success']:
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
                        'folder': _plain_text(folder),
                        'message_id': _plain_text(result['message_id']),
                        'subject': _plain_text(result['subject']),
                        'error': _plain_text(error_msg)
                    })
                    self._save_progress(db, sync_record, counts, failed_emails, new_failure=True)
                    self.mark_as_processed(email_id)

            logger.info(f"Batch {batch_number} complete: "
                       f"{counts['emails_processed']}/{counts['emails_found']} processed, "
                       f"{counts['reports_created']} created, "
                       f"{counts['reports_failed']} failed")

    def _save_progress(self, db, sync_record: DMARCSync, counts: Dict, failed_emails: List[Dict],
                       new_failure: bool = False):
        _record_counts(sync_record, counts)
        sync_record.failed_emails = list(failed_emails) or None
        try:
            db.commit()
        except Exception as error:
            if not (new_failure and _is_value_error(error)):
                raise
            logger.warning(f"Could not store the failure entry of email "
                           f"{failed_emails[-1]['email_id']} ({type(error).__name__})")
            db.rollback()
            failed_emails[-1] = {'email_id': failed_emails[-1]['email_id'],
                                 'folder': failed_emails[-1].get('folder'), 'message_id': None,
                                 'subject': None, 'error': _DETAILS_NOT_STORED}
            _record_counts(sync_record, counts)
            sync_record.failed_emails = list(failed_emails)
            db.commit()

    def _notify_failures(self, failed_emails: List[Dict], sync_id) -> bool:
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


_sync_lock = threading.Lock()


def is_sync_running() -> bool:
    return _sync_lock.locked()


def _fail_interrupted_syncs():
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