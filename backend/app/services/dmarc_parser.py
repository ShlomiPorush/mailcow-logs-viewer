"""
DMARC Report Parser
Handles parsing of DMARC aggregate reports in XML format (GZ or ZIP compressed)
"""
import gzip
import zipfile
import xml.etree.ElementTree as ET
import logging
from typing import Dict, List, Any, Optional
from io import BytesIO

logger = logging.getLogger(__name__)


def parse_dmarc_file(file_content: bytes, filename: str) -> Optional[Dict[str, Any]]:
    """
    Parse DMARC report from compressed file (GZ or ZIP)
    
    Args:
        file_content: Raw bytes of the compressed file
        filename: Original filename (to determine compression type)
        
    Returns:
        Parsed DMARC data or None if parsing failed
    """
    try:
        # Determine file type and extract XML
        xml_content = None
        
        if filename.endswith('.gz'):
            # Gzip compressed
            with gzip.open(BytesIO(file_content), 'rb') as f:
                xml_content = f.read()
                
        elif filename.endswith('.zip'):
            # ZIP compressed (Google uses this)
            with zipfile.ZipFile(BytesIO(file_content)) as z:
                # Get first XML file in zip
                xml_files = [name for name in z.namelist() if name.endswith('.xml')]
                if xml_files:
                    xml_content = z.read(xml_files[0])
                else:
                    logger.error(f"No XML file found in ZIP: {filename}")
                    return None
        else:
            logger.error(f"Unsupported file format: {filename}")
            return None
        
        if not xml_content:
            logger.error(f"Failed to extract XML content from {filename}")
            return None
        
        # Parse XML
        return parse_dmarc_xml(xml_content.decode('utf-8'), xml_content.decode('utf-8'))
        
    except Exception as e:
        logger.error(f"Error parsing DMARC file {filename}: {e}")
        return None


def find_element(parent: ET.Element, tag: str, namespaces: List[str]) -> Optional[ET.Element]:
    """
    Find an element trying multiple namespaces
    
    Args:
        parent: Parent XML element
        tag: Tag name to find
        namespaces: List of namespace prefixes to try (empty string for no namespace)
        
    Returns:
        Found element or None
    """
    for ns in namespaces:
        if ns:
            elem = parent.find(f'{{{ns}}}{tag}')
        else:
            elem = parent.find(tag)
        if elem is not None:
            return elem
    return None


def find_all_elements(parent: ET.Element, tag: str, namespaces: List[str]) -> List[ET.Element]:
    """
    Find all elements matching tag, trying multiple namespaces
    
    Args:
        parent: Parent XML element
        tag: Tag name to find
        namespaces: List of namespace prefixes to try
        
    Returns:
        List of found elements
    """
    for ns in namespaces:
        if ns:
            elems = parent.findall(f'{{{ns}}}{tag}')
        else:
            elems = parent.findall(tag)
        if elems:
            return elems
    return []


# Known DMARC XML namespaces
DMARC_NAMESPACES = [
    '',  # No namespace (DMARC 1.0)
    'urn:ietf:params:xml:ns:dmarc-2.0',  # DMARC 2.0
]


def parse_dmarc_xml(xml_string: str, raw_xml: str) -> Dict[str, Any]:
    """
    Parse DMARC XML content
    
    Args:
        xml_string: XML content as string
        raw_xml: Original raw XML for storage
        
    Returns:
        Dictionary with parsed DMARC data
    """
    try:
        root = ET.fromstring(xml_string)
        
        # Parse report metadata (try with and without namespace)
        metadata = find_element(root, 'report_metadata', DMARC_NAMESPACES)
        if metadata is None:
            raise ValueError("Missing report_metadata element")
        
        org_name = get_element_text(metadata, 'org_name', DMARC_NAMESPACES)
        email = get_element_text(metadata, 'email', DMARC_NAMESPACES)
        extra_contact_info = get_element_text(metadata, 'extra_contact_info', DMARC_NAMESPACES)
        report_id = get_element_text(metadata, 'report_id', DMARC_NAMESPACES)
        
        date_range = find_element(metadata, 'date_range', DMARC_NAMESPACES)
        if date_range is None:
            raise ValueError("Missing date_range element")
        
        begin_date = int(get_element_text(date_range, 'begin', DMARC_NAMESPACES))
        end_date = int(get_element_text(date_range, 'end', DMARC_NAMESPACES))
        
        # Parse published policy
        policy = find_element(root, 'policy_published', DMARC_NAMESPACES)
        if policy is None:
            raise ValueError("Missing policy_published element")
        
        domain = get_element_text(policy, 'domain', DMARC_NAMESPACES)
        
        policy_published = {
            'adkim': get_element_text(policy, 'adkim', DMARC_NAMESPACES),
            'aspf': get_element_text(policy, 'aspf', DMARC_NAMESPACES),
            'p': get_element_text(policy, 'p', DMARC_NAMESPACES),
            'sp': get_element_text(policy, 'sp', DMARC_NAMESPACES),
            'pct': get_element_text(policy, 'pct', DMARC_NAMESPACES),
            'fo': get_element_text(policy, 'fo', DMARC_NAMESPACES),
            'np': get_element_text(policy, 'np', DMARC_NAMESPACES),
        }
        
        # Remove None values
        policy_published = {k: v for k, v in policy_published.items() if v is not None}
        
        # Parse records
        records = []
        for record_elem in find_all_elements(root, 'record', DMARC_NAMESPACES):
            record_data = parse_dmarc_record(record_elem)
            if record_data:
                records.append(record_data)
        
        return {
            'report_id': report_id,
            'org_name': org_name,
            'email': email,
            'extra_contact_info': extra_contact_info,
            'domain': domain,
            'begin_date': begin_date,
            'end_date': end_date,
            'policy_published': policy_published,
            'records': records,
            'raw_xml': raw_xml
        }
        
    except Exception as e:
        logger.error(f"Error parsing DMARC XML: {e}")
        raise


def parse_dmarc_record(record_elem: ET.Element) -> Optional[Dict[str, Any]]:
    """
    Parse a single DMARC record element
    
    Args:
        record_elem: XML element for a record
        
    Returns:
        Dictionary with parsed record data
    """
    try:
        row = find_element(record_elem, 'row', DMARC_NAMESPACES)
        if row is None:
            return None
        
        # Source and count
        source_ip = get_element_text(row, 'source_ip', DMARC_NAMESPACES)
        count = int(get_element_text(row, 'count', DMARC_NAMESPACES, '0'))
        
        # Policy evaluation
        policy_eval = find_element(row, 'policy_evaluated', DMARC_NAMESPACES)
        disposition = get_element_text(policy_eval, 'disposition', DMARC_NAMESPACES) if policy_eval else None
        dkim_result = get_element_text(policy_eval, 'dkim', DMARC_NAMESPACES) if policy_eval else None
        spf_result = get_element_text(policy_eval, 'spf', DMARC_NAMESPACES) if policy_eval else None
        
        # Identifiers
        identifiers = find_element(record_elem, 'identifiers', DMARC_NAMESPACES)
        header_from = get_element_text(identifiers, 'header_from', DMARC_NAMESPACES) if identifiers else None
        envelope_from = get_element_text(identifiers, 'envelope_from', DMARC_NAMESPACES) if identifiers else None
        envelope_to = get_element_text(identifiers, 'envelope_to', DMARC_NAMESPACES) if identifiers else None
        
        # Auth results
        auth_results = {}
        auth_results_elem = find_element(record_elem, 'auth_results', DMARC_NAMESPACES)
        
        if auth_results_elem:
            # Parse DKIM results
            dkim_results = []
            for dkim_elem in find_all_elements(auth_results_elem, 'dkim', DMARC_NAMESPACES):
                dkim_data = {
                    'domain': get_element_text(dkim_elem, 'domain', DMARC_NAMESPACES),
                    'selector': get_element_text(dkim_elem, 'selector', DMARC_NAMESPACES),
                    'result': get_element_text(dkim_elem, 'r', DMARC_NAMESPACES) or get_element_text(dkim_elem, 'result', DMARC_NAMESPACES)
                }
                dkim_results.append({k: v for k, v in dkim_data.items() if v})
            
            if dkim_results:
                auth_results['dkim'] = dkim_results
            
            # Parse SPF results
            spf_results = []
            for spf_elem in find_all_elements(auth_results_elem, 'spf', DMARC_NAMESPACES):
                spf_data = {
                    'domain': get_element_text(spf_elem, 'domain', DMARC_NAMESPACES),
                    'scope': get_element_text(spf_elem, 'scope', DMARC_NAMESPACES),
                    'result': get_element_text(spf_elem, 'r', DMARC_NAMESPACES) or get_element_text(spf_elem, 'result', DMARC_NAMESPACES)
                }
                spf_results.append({k: v for k, v in spf_data.items() if v})
            
            if spf_results:
                auth_results['spf'] = spf_results
        
        return {
            'source_ip': source_ip,
            'count': count,
            'disposition': disposition,
            'dkim_result': dkim_result,
            'spf_result': spf_result,
            'header_from': header_from,
            'envelope_from': envelope_from,
            'envelope_to': envelope_to,
            'auth_results': auth_results if auth_results else None
        }
        
    except Exception as e:
        logger.error(f"Error parsing DMARC record: {e}")
        return None


def get_element_text(parent: Optional[ET.Element], tag: str, namespaces: List[str] = None, default: Optional[str] = None) -> Optional[str]:
    """
    Safely get text from XML element with namespace support
    
    Args:
        parent: Parent XML element
        tag: Tag name to find
        namespaces: List of namespace prefixes to try
        default: Default value if not found
        
    Returns:
        Element text or default value
    """
    if parent is None:
        return default
    
    if namespaces:
        elem = find_element(parent, tag, namespaces)
    else:
        elem = parent.find(tag)
    
    if elem is not None and elem.text:
        return elem.text.strip()
    
    return default