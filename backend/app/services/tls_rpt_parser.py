"""
TLS-RPT (SMTP TLS Reporting) Parser
Handles parsing of TLS-RPT reports in JSON format
"""
import json
import gzip
import zipfile
import logging
from typing import Dict, Any, Optional
from datetime import datetime
from io import BytesIO

logger = logging.getLogger(__name__)


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
        
        # Handle ZIP files (.json.zip)
        if filename_lower.endswith('.zip'):
            try:
                with zipfile.ZipFile(BytesIO(file_content)) as zf:
                    # Find JSON file inside ZIP
                    json_files = [f for f in zf.namelist() if f.lower().endswith('.json')]
                    if not json_files:
                        logger.error(f"No JSON file found in ZIP: {filename}")
                        return None
                    
                    # Read the first JSON file
                    json_content = zf.read(json_files[0]).decode('utf-8')
            except zipfile.BadZipFile as e:
                logger.error(f"Invalid ZIP file {filename}: {e}")
                return None
        # Handle GZIP files (.json.gz)
        elif filename_lower.endswith('.gz'):
            try:
                json_content = gzip.decompress(file_content).decode('utf-8')
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
        
        # Extract report metadata
        report_id = data.get('report-id', '')
        if not report_id:
            logger.error("TLS-RPT report missing report-id")
            return None
        
        organization_name = data.get('organization-name', 'Unknown')
        contact_info = data.get('contact-info', '')
        
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
        
        for policy_entry in data.get('policies', []):
            policy_data = policy_entry.get('policy', {})
            summary = policy_entry.get('summary', {})
            
            # Get the policy domain from the first policy
            if not policy_domain:
                policy_domain = policy_data.get('policy-domain', '')
            
            parsed_policy = {
                'policy_type': policy_data.get('policy-type', 'unknown'),
                'policy_domain': policy_data.get('policy-domain', ''),
                'policy_string': policy_data.get('policy-string', []),
                'mx_host': policy_data.get('mx-host', []),
                'successful_session_count': summary.get('total-successful-session-count', 0),
                'failed_session_count': summary.get('total-failure-session-count', 0),
                'failure_details': policy_entry.get('failure-details', [])
            }
            policies.append(parsed_policy)
        
        if not policy_domain:
            logger.error("TLS-RPT report missing policy-domain")
            return None
        
        return {
            'report_id': report_id,
            'organization_name': organization_name,
            'contact_info': contact_info,
            'policy_domain': policy_domain,
            'start_datetime': start_datetime,
            'end_datetime': end_datetime,
            'policies': policies,
            'raw_json': json_content
        }
        
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in TLS-RPT report: {e}")
        return None
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
