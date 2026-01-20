"""
DMARC & TLS-RPT IMAP Service
Automatically fetches and processes DMARC and TLS-RPT reports from email inbox
"""
import logging
import imaplib
import email
import gzip
import zipfile
import io
import json
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple
from email.message import EmailMessage

from ..config import settings
from ..database import SessionLocal
from ..models import DMARCSync, DMARCReport, DMARCRecord, TLSReport, TLSReportPolicy
from ..services.dmarc_parser import parse_dmarc_file
from ..services.tls_rpt_parser import parse_tls_rpt_file, is_tls_rpt_json
from ..services.geoip_service import enrich_dmarc_record
from ..services.dmarc_notifications import send_dmarc_error_notification
from ..services.dmarc_cache import clear_dmarc_cache

logger = logging.getLogger(__name__)


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
        self.connection = None
        
    def connect(self) -> bool:
        """Connect to IMAP server"""
        try:
            if self.use_ssl:
                self.connection = imaplib.IMAP4_SSL(self.host, self.port, timeout=30)
            else:
                self.connection = imaplib.IMAP4(self.host, self.port, timeout=30)
            
            self.connection.login(self.user, self.password)
            logger.info(f"Successfully connected to IMAP server {self.host}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to IMAP server: {e}")
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
        Search for DMARC and TLS-RPT report emails
        
        Looking for emails with subject containing:
        - "Report Domain:" (DMARC)
        - "DMARC" (DMARC)
        - "Report-ID:" (DMARC)
        - "TLS-RPT" (TLS-RPT)
        - "TLS Report" (TLS-RPT)
        
        Returns list of email IDs
        """
        try:
            # Search for emails with DMARC or TLS-RPT related subjects
            # Using OR to be more flexible
            # UNSEEN ensures we don't re-process emails that were already handled (marked as Seen)
            search_criteria = '(UNSEEN (OR (SUBJECT "Report Domain:") (OR (SUBJECT "DMARC") (OR (SUBJECT "Report-ID:") (OR (SUBJECT "TLS-RPT") (SUBJECT "TLS Report"))))))'
            
            status, messages = self.connection.uid('SEARCH', None, search_criteria)
            
            if status != 'OK':
                logger.error("Failed to search for report emails")
                return []
            
            email_ids = messages[0].split()
            logger.info(f"Found {len(email_ids)} potential DMARC/TLS-RPT emails")
            
            return email_ids
            
        except Exception as e:
            logger.error(f"Error searching for emails: {e}")
            return []
    
    def search_dmarc_emails(self) -> List[bytes]:
        """Alias for backward compatibility"""
        return self.search_report_emails()
    
    def is_valid_dmarc_email(self, msg: EmailMessage) -> bool:
        """
        Validate that this is a genuine DMARC report email
        
        Accepts multiple DMARC email formats:
        - Standard: "Report Domain: X Submitter: Y Report-ID: Z"
        - Yahoo format: "Report Domain: X Submitter: Y" (no Report-ID)
        - Alternative: Contains "DMARC" in subject
        - Microsoft Outlook: DMARC-like attachment filename pattern
        
        Primary validation is the attachment (.xml.gz or .zip with DMARC content)
        """
        try:
            subject = msg.get('subject', '').lower()
            
            # Check for compressed DMARC attachments FIRST (most reliable indicator)
            has_dmarc_attachment = False
            has_dmarc_filename = False
            
            for part in msg.walk():
                filename = part.get_filename()
                if filename:
                    filename_lower = filename.lower()
                    # DMARC reports come as .xml.gz, .xml, or .zip files
                    if filename_lower.endswith('.xml.gz') or filename_lower.endswith('.zip') or filename_lower.endswith('.xml'):
                        has_dmarc_attachment = True
                        # Check if filename looks like a DMARC report
                        # Microsoft format: enterprise.protection.outlook.com!domain!timestamp!timestamp.xml.gz
                        # Standard format: domain!report-domain!timestamp!timestamp.xml.gz
                        if '!' in filename and (filename_lower.endswith('.xml.gz') or filename_lower.endswith('.xml') or filename_lower.endswith('.zip')):
                            has_dmarc_filename = True
                        break
            
            if not has_dmarc_attachment:
                logger.debug(f"Email has no compressed DMARC attachment: {subject}")
                return False
            
            # Check subject format - be flexible to support different providers
            has_report_domain = 'report domain:' in subject
            has_submitter = 'submitter:' in subject
            has_report_id = 'report-id:' in subject
            has_dmarc_keyword = 'dmarc' in subject
            
            # Accept if:
            # 1. Has "Report Domain:" and ("Submitter:" or "Report-ID:") - standard format
            # 2. Has "Report Domain:" only (Yahoo and others) - we have verified attachment
            # 3. Has "DMARC" keyword in subject with valid attachment
            # 4. Has DMARC-like filename pattern (Microsoft Outlook and others) - attachment name contains '!'
            is_valid_subject = (
                (has_report_domain and (has_submitter or has_report_id)) or  # Standard format
                (has_report_domain) or  # Yahoo/minimal format (attachment already verified)
                (has_dmarc_keyword) or  # DMARC keyword with attachment
                (has_dmarc_filename)  # Microsoft Outlook format - DMARC filename pattern
            )
            
            if not is_valid_subject:
                logger.debug(f"Email does not match DMARC subject/filename pattern: {subject}")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating DMARC email: {e}")
            return False
    
    def is_valid_tls_rpt_email(self, msg: EmailMessage) -> bool:
        """
        Validate that this is a TLS-RPT report email
        
        TLS-RPT emails typically have:
        - Subject containing "TLS-RPT" or "TLS Report"
        - JSON or JSON.GZ attachment
        - Some providers send with generic subjects like "Report Domain: ..."
        """
        try:
            subject = msg.get('subject', '').lower()
            
            # Check for JSON/ZIP attachments
            has_json_attachment = False
            
            for part in msg.walk():
                filename = part.get_filename()
                if filename:
                    filename_lower = filename.lower()
                    if filename_lower.endswith('.json') or filename_lower.endswith('.json.gz') or filename_lower.endswith('.zip'):
                        has_json_attachment = True
                        break
            
            if not has_json_attachment:
                return False
            
            # Trust the attachment if it looks like a TLS report
            # If it has a json/gz/zip attachment, we should try to process it as potential TLS-RPT
            # The parser will validate the content anyway
            return True
            
        except Exception as e:
            logger.error(f"Error validating TLS-RPT email: {e}")
            return False
    
    def detect_email_type(self, msg: EmailMessage) -> str:
        """
        Detect if email is DMARC or TLS-RPT by inspecting attachments
        
        Returns: 'dmarc', 'tls-rpt', or 'unknown'
        """
        try:
            # Check attachments FIRST - content is king
            for part in msg.walk():
                filename = part.get_filename()
                if not filename:
                    continue
                    
                filename_lower = filename.lower()
                content = None
                
                # Check explicit extensions
                if filename_lower.endswith('.xml.gz') or filename_lower.endswith('.xml'):
                    return 'dmarc'
                
                if filename_lower.endswith('.json.gz') or filename_lower.endswith('.json'):
                    return 'tls-rpt'
                
                # Check ZIP content
                if filename_lower.endswith('.zip'):
                    try:
                        content = part.get_payload(decode=True)
                        if content:
                            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                                for name in zf.namelist():
                                    name_lower = name.lower()
                                    if name_lower.endswith('.xml'):
                                        logger.info(f"Found XML in ZIP {filename}, identifying as DMARC")
                                        return 'dmarc'
                                    if name_lower.endswith('.json'):
                                        logger.info(f"Found JSON in ZIP {filename}, identifying as TLS-RPT")
                                        return 'tls-rpt'
                    except Exception as e:
                        logger.warning(f"Failed to inspect ZIP {filename}: {e}")
                        
            # Fallback to subject/header heuristics if no clear attachment type found
            # but reject ambiguous ZIPs that we couldn't inspect or were empty of relevant files
            
            if self.is_valid_tls_rpt_email(msg):
                return 'tls-rpt'
            elif self.is_valid_dmarc_email(msg):
                return 'dmarc'
                
            return 'unknown'
            
        except Exception as e:
            logger.error(f"Error detecting email type: {e}")
            return 'unknown'
    
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
    
    def process_email(self, email_id: str, db: SessionLocal) -> Dict:
        """
        Process a single DMARC or TLS-RPT email
        
        Returns dict with:
        - success: bool
        - reports_created: int
        - reports_duplicate: int
        - error: str or None
        - report_type: 'dmarc' or 'tls-rpt'
        """
        result = {
            'success': False,
            'reports_created': 0,
            'reports_duplicate': 0,
            'error': None,
            'message_id': None,
            'subject': None,
            'report_type': None
        }
        
        try:
            # Fetch email (email_id is already a string)
            status, msg_data = self.connection.uid('FETCH', email_id, '(RFC822)')
            
            if status != 'OK':
                result['error'] = f"Failed to fetch email {email_id}"
                return result
            
            # Parse email
            msg = email.message_from_bytes(msg_data[0][1])
            result['message_id'] = msg.get('message-id', 'unknown')
            result['subject'] = msg.get('subject', 'unknown')
            
            # Detect email type
            email_type = self.detect_email_type(msg)
            result['report_type'] = email_type
            
            if email_type == 'tls-rpt':
                return self._process_tls_rpt_email(msg, db, result)
            elif email_type == 'dmarc':
                return self._process_dmarc_email(msg, db, result)
            else:
                result['error'] = "Not a valid DMARC or TLS-RPT report email"
                return result
            
        except Exception as e:
            logger.error(f"Error processing email {email_id}: {e}")
            result['error'] = str(e)
            return result
    
    def _process_dmarc_email(self, msg: EmailMessage, db: SessionLocal, result: Dict) -> Dict:
        """Process a DMARC email"""
        # Extract attachments (DMARC: XML files)
        attachments = self.extract_attachments(msg, include_json=False)
        
        if not attachments:
            result['error'] = "No DMARC attachments found"
            return result
        
        # Process each attachment
        attachment_errors = []
        for filename, content in attachments:
            try:
                # Parse DMARC report
                parsed_data = parse_dmarc_file(content, filename)
                
                if not parsed_data:
                    attachment_errors.append(f"Failed to parse: {filename}")
                    logger.warning(f"Failed to parse attachment: {filename}")
                    continue
                
                # Extract records
                records_data = parsed_data.pop('records', [])
                report_data = parsed_data
                
                # Check for duplicate
                existing = db.query(DMARCReport).filter(
                    DMARCReport.report_id == report_data['report_id']
                ).first()
                
                if existing:
                    result['reports_duplicate'] += 1
                    logger.info(f"Duplicate report: {report_data['report_id']}")
                    continue
                
                # Create report
                report = DMARCReport(**report_data)
                db.add(report)
                db.flush()
                
                # Create records with GeoIP enrichment
                for record_data in records_data:
                    record_data['dmarc_report_id'] = report.id
                    enriched = enrich_dmarc_record(record_data)
                    record = DMARCRecord(**enriched)
                    db.add(record)
                
                db.commit()
                result['reports_created'] += 1
                logger.info(f"Created DMARC report: {report_data['report_id']}")
                
            except Exception as e:
                db.rollback()
                error_msg = f"Error processing {filename}: {str(e)}"
                attachment_errors.append(error_msg)
                logger.error(error_msg)
        
        # Determine success
        return self._finalize_result(result, attachment_errors, "DMARC")
    
    def _process_tls_rpt_email(self, msg: EmailMessage, db: SessionLocal, result: Dict) -> Dict:
        """Process a TLS-RPT email"""
        # Extract attachments (TLS-RPT: JSON files)
        attachments = self.extract_attachments(msg, include_json=True)
        
        # Filter to only JSON files (and ZIPs containing JSON)
        json_attachments = [(f, c) for f, c in attachments if f.lower().endswith('.json') or f.lower().endswith('.json.gz') or f.lower().endswith('.zip')]
        
        if not json_attachments:
            result['error'] = "No TLS-RPT JSON attachments found"
            return result
        
        # Process each attachment
        attachment_errors = []
        for filename, content in json_attachments:
            try:
                # Parse TLS-RPT report
                parsed_data = parse_tls_rpt_file(content, filename)
                
                if not parsed_data:
                    attachment_errors.append(f"Failed to parse: {filename}")
                    logger.warning(f"Failed to parse TLS-RPT attachment: {filename}")
                    continue
                
                # Extract policies
                policies_data = parsed_data.pop('policies', [])
                
                # Check for duplicate
                existing = db.query(TLSReport).filter(
                    TLSReport.report_id == parsed_data['report_id']
                ).first()
                
                if existing:
                    result['reports_duplicate'] += 1
                    logger.info(f"Duplicate TLS-RPT report: {parsed_data['report_id']}")
                    continue
                
                # Create TLS report
                tls_report = TLSReport(
                    report_id=parsed_data['report_id'],
                    organization_name=parsed_data.get('organization_name', 'Unknown'),
                    contact_info=parsed_data.get('contact_info', ''),
                    policy_domain=parsed_data['policy_domain'],
                    start_datetime=parsed_data['start_datetime'],
                    end_datetime=parsed_data['end_datetime'],
                    raw_json=parsed_data.get('raw_json', '')
                )
                db.add(tls_report)
                db.flush()
                
                # Create policy records
                for policy_data in policies_data:
                    policy = TLSReportPolicy(
                        tls_report_id=tls_report.id,
                        policy_type=policy_data.get('policy_type', 'unknown'),
                        policy_domain=policy_data.get('policy_domain', ''),
                        policy_string=policy_data.get('policy_string', []),
                        mx_host=policy_data.get('mx_host', []),
                        successful_session_count=policy_data.get('successful_session_count', 0),
                        failed_session_count=policy_data.get('failed_session_count', 0),
                        failure_details=policy_data.get('failure_details', [])
                    )
                    db.add(policy)
                
                db.commit()
                result['reports_created'] += 1
                logger.info(f"Created TLS-RPT report: {parsed_data['report_id']}")
                
            except Exception as e:
                db.rollback()
                error_msg = f"Error processing TLS-RPT {filename}: {str(e)}"
                attachment_errors.append(error_msg)
                logger.error(error_msg)
        
        # Determine success
        return self._finalize_result(result, attachment_errors, "TLS-RPT")
    
    def _finalize_result(self, result: Dict, attachment_errors: List[str], report_type: str) -> Dict:
        """Finalize the result based on processing outcome"""
        if result['reports_created'] > 0:
            result['success'] = True
        elif result['reports_duplicate'] > 0 and result['reports_created'] == 0:
            # All reports were duplicates - this is actually OK, mark as success
            result['success'] = True
            result['error'] = None  # No error - duplicates are expected
        else:
            # No reports created and no duplicates - something went wrong
            result['success'] = False
            if attachment_errors:
                result['error'] = "; ".join(attachment_errors)
            else:
                result['error'] = f"No valid {report_type} reports found in attachments"
        
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
        
        Returns statistics about the sync operation
        """
        sync_record = DMARCSync(
            sync_type=sync_type,
            started_at=datetime.now(timezone.utc),
            status='running'
        )
        
        db = SessionLocal()
        batch_size = settings.dmarc_imap_batch_size
        
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
            failed_emails = []
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
                    sync_record.emails_processed += 1
                    
                    if result['success']:
                        sync_record.reports_created += result['reports_created']
                        sync_record.reports_duplicate += result['reports_duplicate']
                        
                        # Delete or mark as processed
                        if self.delete_after:
                            self.delete_email(email_id)
                        else:
                            self.mark_as_processed(email_id)
                    else:
                        sync_record.reports_failed += 1
                        error_msg = result.get('error', 'Unknown error')
                        logger.warning(f"Failed to process email {email_id}: {error_msg}")
                        
                        failed_emails.append({
                            'email_id': email_id,
                            'message_id': result['message_id'],
                            'subject': result['subject'],
                            'error': error_msg
                        })
                        # Also mark failed emails as processed to avoid re-processing
                        self.mark_as_processed(email_id)
                    
                    db.commit()
                
                # Log batch progress
                logger.info(f"Batch {batch_number} complete: "
                           f"{sync_record.emails_processed}/{total_emails} processed, "
                           f"{sync_record.reports_created} created, "
                           f"{sync_record.reports_failed} failed")
            
            # Update sync record
            sync_record.status = 'success'
            sync_record.completed_at = datetime.now(timezone.utc)
            sync_record.failed_emails = failed_emails if failed_emails else None
            
            if failed_emails:
                sync_record.error_message = f"{len(failed_emails)} emails failed to process"
            
            db.commit()
            
            logger.info(f"DMARC sync completed: {sync_record.reports_created} created, "
                       f"{sync_record.reports_duplicate} duplicates, "
                       f"{sync_record.reports_failed} failed")
            
            # Clear cache if any reports were created
            if sync_record.reports_created > 0:
                clear_dmarc_cache(db)
            
            # Send email notification if there were failures
            if failed_emails and settings.notification_smtp_configured:
                logger.info(f"Sending error notification for {len(failed_emails)} failed emails")
                try:
                    send_dmarc_error_notification(failed_emails, sync_record.id)
                    logger.info("Error notification sent successfully")
                except Exception as email_error:
                    logger.error(f"Failed to send error notification: {email_error}")
            
            return self._build_result(sync_record)
            
        except Exception as e:
            logger.error(f"DMARC sync failed: {e}")
            
            sync_record.status = 'error'
            sync_record.completed_at = datetime.now(timezone.utc)
            sync_record.error_message = str(e)
            db.commit()
            
            raise
            
        finally:
            self.disconnect()
            db.close()
    
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
    
    service = DMARCImapService()
    return service.sync_reports(sync_type=sync_type)