"""
TLS-RPT (SMTP TLS Reporting) Parser
Handles parsing of TLS-RPT reports in JSON format
"""
import json
import zipfile
import logging
from typing import Dict, Any, Optional
from datetime import datetime
from io import BytesIO

from .dmarc_parser import is_valid_domain_name
from .safe_decompress import (
    DecompressionLimitError,
    MAX_COMPRESSED_BYTES,
    gzip_decompress_limited,
    zip_read_limited,
)
from .report_identity import (
    MAX_REPORT_ITEMS,
    MAX_STORED_COUNT,
    REPORT_TOO_LARGE,
    ReportLimitError,
    ReportRejectedError,
    zip_report_member,
)

logger = logging.getLogger(__name__)


def _text(data: dict, key: str, default):
    """A text field of the report: the default when it is missing, None when
    it is null, as stored before. RFC 8460 makes them JSON strings; anything
    else is refused rather than turned into text by the database."""
    value = data.get(key, default)
    if value is not None and not isinstance(value, str):
        raise ValueError("A text field of the report is not a string")
    return value


def _session_count(summary: dict, key: str):
    """0 when missing, None when null, as stored before; else a whole number in range."""
    value = summary.get(key, 0)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_STORED_COUNT:
        raise ValueError("A session count of the report is not a whole number in range")
    return value


def parse_tls_rpt_file(file_content: bytes, filename: str) -> Optional[Dict[str, Any]]:
    """
    Parse TLS-RPT report from file content (JSON, GZ compressed, or ZIP)
    
    Args:
        file_content: Raw bytes of the file
        filename: Original filename (to determine compression type)
        
    Returns:
        Parsed TLS-RPT data or None if parsing failed
    """
    try:
        filename_lower = filename.lower()

        if len(file_content) > MAX_COMPRESSED_BYTES:
            logger.error(f"TLS-RPT file {filename} exceeds compressed size limit, rejecting")
            raise ReportLimitError(REPORT_TOO_LARGE)

        # Handle ZIP files (.json.zip)
        if filename_lower.endswith('.zip'):
            try:
                with zipfile.ZipFile(BytesIO(file_content)) as zf:
                    # The one JSON report in the ZIP
                    json_file = zip_report_member(zf, '.json')
                    if not json_file:
                        logger.error(f"No JSON file found in ZIP: {filename}")
                        return None

                    json_content = zip_read_limited(zf, json_file, source=filename).decode('utf-8')
            except zipfile.BadZipFile as e:
                logger.error(f"Invalid ZIP file {filename}: {e}")
                return None
        # Handle GZIP files (.json.gz)
        elif filename_lower.endswith('.gz'):
            try:
                json_content = gzip_decompress_limited(file_content, source=filename).decode('utf-8')
            except DecompressionLimitError:
                raise
            except Exception as e:
                logger.error(f"Failed to decompress gzip TLS-RPT file: {e}")
                return None
        # Handle plain JSON files
        elif filename_lower.endswith('.json'):
            json_content = file_content.decode('utf-8')
        else:
            # Try to decode as JSON directly
            try:
                json_content = file_content.decode('utf-8')
            except Exception:
                logger.error(f"Unknown TLS-RPT file format: {filename}")
                return None
        
        return parse_tls_rpt_json(json_content)

    except DecompressionLimitError as e:
        # A limit: nothing from the email or upload is imported
        logger.error(f"Rejected oversized TLS-RPT file {filename}: {e}")
        raise ReportLimitError(REPORT_TOO_LARGE) from e
    except ReportRejectedError:
        # The caller says why; a limit rejects the whole email or upload
        raise
    except Exception as e:
        logger.error(f"Error parsing TLS-RPT file {filename}: {e}")
        return None



def parse_tls_rpt_json(json_content: str) -> Optional[Dict[str, Any]]:
    """
    Parse TLS-RPT JSON content
    
    Expected format (RFC 8460):
    {
        "organization-name": "Google Inc.",
        "date-range": {
            "start-datetime": "2026-01-12T00:00:00Z",
            "end-datetime": "2026-01-12T23:59:59Z"
        },
        "contact-info": "smtp-tls-reporting@google.com",
        "report-id": "2026-01-12T00:00:00Z_boubou.me",
        "policies": [{
            "policy": {
                "policy-type": "sts",
                "policy-string": ["version: STSv1", "mode: enforce", ...],
                "policy-domain": "boubou.me",
                "mx-host": ["mail.tiboxs.com"]
            },
            "summary": {
                "total-successful-session-count": 1,
                "total-failure-session-count": 0
            },
            "failure-details": [...]  # Optional
        }]
    }
    
    Returns:
        Dictionary with parsed TLS-RPT data
    """
    try:
        data = json.loads(json_content)
        
        # Extract report metadata. The values are stored as they are and the
        # report's identity is computed from them, so their types are checked.
        report_id = _text(data, 'report-id', '')
        if not report_id:
            logger.error("TLS-RPT report missing report-id")
            return None

        organization_name = _text(data, 'organization-name', 'Unknown')
        contact_info = _text(data, 'contact-info', '')

        # Parse date range
        date_range = data.get('date-range', {})
        start_datetime = parse_iso_datetime(date_range.get('start-datetime', ''))
        end_datetime = parse_iso_datetime(date_range.get('end-datetime', ''))

        if not start_datetime or not end_datetime:
            logger.error("TLS-RPT report missing or invalid date-range")
            return None

        # Parse policies
        policies = []
        policy_domain = None
        entries = data.get('policies', [])
        if not isinstance(entries, list):
            raise ValueError("policies is not a list")
        items = 0

        for policy_entry in entries:
            policy_data = policy_entry.get('policy', {})
            summary = policy_entry.get('summary', {})
            failure_details = policy_entry.get('failure-details', [])
            if failure_details is not None and not isinstance(failure_details, list):
                raise ValueError("failure-details is not a list")
            items += 1 + len(failure_details or [])
            if items > MAX_REPORT_ITEMS:
                raise ReportLimitError(
                    f"The report has more than {MAX_REPORT_ITEMS:,} policies and failure details.")

            # Get the policy domain from the first policy
            if not policy_domain:
                policy_domain = _text(policy_data, 'policy-domain', '')

            parsed_policy = {
                'policy_type': _text(policy_data, 'policy-type', 'unknown'),
                'policy_domain': _text(policy_data, 'policy-domain', ''),
                'policy_string': policy_data.get('policy-string', []),
                'mx_host': policy_data.get('mx-host', []),
                'successful_session_count': _session_count(summary, 'total-successful-session-count'),
                'failed_session_count': _session_count(summary, 'total-failure-session-count'),
                'failure_details': failure_details
            }
            policies.append(parsed_policy)
        
        if not policy_domain:
            logger.error("TLS-RPT report missing policy-domain")
            return None
        if not all(is_valid_domain_name(p['policy_domain']) for p in policies):
            logger.error("TLS-RPT report has a policy-domain that is not a valid domain name")
            return None
        
        return {
            'report_id': report_id,
            'organization_name': organization_name,
            'contact_info': contact_info,
            'policy_domain': policy_domain,
            'start_datetime': start_datetime,
            'end_datetime': end_datetime,
            'policies': policies,
        }
        
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in TLS-RPT report: {e}")
        return None
    except ReportRejectedError:
        raise
    except Exception as e:
        logger.error(f"Error parsing TLS-RPT JSON: {e}")
        return None


def parse_iso_datetime(datetime_str: str) -> Optional[datetime]:
    """
    Parse ISO 8601 datetime string
    
    Supports formats:
    - 2026-01-12T00:00:00Z
    - 2026-01-12T00:00:00+00:00
    """
    if not datetime_str:
        return None
    
    try:
        # Remove 'Z' suffix and replace with +00:00 for parsing
        if datetime_str.endswith('Z'):
            datetime_str = datetime_str[:-1] + '+00:00'
        
        # Parse with timezone
        from datetime import timezone
        dt = datetime.fromisoformat(datetime_str)
        
        # Convert to UTC naive datetime for storage
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        
        return dt
        
    except Exception as e:
        logger.error(f"Error parsing datetime '{datetime_str}': {e}")
        return None


def is_tls_rpt_json(json_content: str) -> bool:
    """
    Check if JSON content is a valid TLS-RPT report
    
    Used to detect TLS-RPT vs other JSON files
    """
    try:
        data = json.loads(json_content)
        
        # Check for required TLS-RPT fields
        has_report_id = 'report-id' in data
        has_date_range = 'date-range' in data
        has_policies = 'policies' in data
        
        # At minimum, should have policies and date-range
        return has_policies and (has_date_range or has_report_id)
        
    except Exception:
        return False
