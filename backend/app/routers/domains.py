"""
API endpoints for domains management with DNS validation
"""
import logging
import re
import asyncio
import ipaddress
from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any, List, Optional
import dns.resolver
import dns.rcode
import httpx
import dns.asyncresolver
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import text, func
from app.database import get_db, get_db_context
from app.models import DomainDNSCheck, DMARCReport, DMARCRecord
from app.services.alias_domains import get_alias_domain_map, aliases_of_domain
from app.utils import format_datetime_for_api
from app.config import settings
from app.mailcow_api import mailcow_api
from ..utils import internal_error

logger = logging.getLogger(__name__)

router = APIRouter()

_server_ip_cache = None


async def init_server_ip():
    """
    Initialize and cache server IP address from mailcow API
    Called once during application startup
    """
    global _server_ip_cache
    
    if _server_ip_cache is not None:
        return _server_ip_cache
    
    try:
        _server_ip_cache = await mailcow_api.get_status_host_ip()
        if _server_ip_cache:
            logger.info(f"Server IP cached successfully: {_server_ip_cache}")
        else:
            logger.warning("Could not fetch server IP from mailcow - no valid IP in response")
        return _server_ip_cache
        
    except Exception as e:
        logger.error(f"Failed to fetch server IP: {type(e).__name__} - {str(e)}")
        return None


def get_cached_server_ip() -> str:
    """
    Get the cached server IP address
    Returns None if not yet cached or failed to fetch
    """
    global _server_ip_cache
    return _server_ip_cache


async def resolve_dns_with_fallback(query: str, record_type: str = 'TXT', timeout: int = 5):
    """
    Resolve DNS query with fallback to multiple DNS servers.
    Uses UDP first, with automatic DoH fallback when UDP port 53 is blocked.
    
    Args:
        query: DNS query (domain name)
        record_type: DNS record type ('TXT', 'A', 'MX', etc.)
        timeout: Timeout in seconds for each query
        
    Returns:
        DNS answer object
        
    Raises:
        dns.resolver.NXDOMAIN: If domain doesn't exist (after trying all servers)
        dns.resolver.NoAnswer: If no answer (after trying all servers)
        Exception: If all DNS servers fail
    """
    from app.services.dns_resolver import resolve
    return await resolve(query, record_type, timeout)


async def _resolve_public_host_ips(host: str) -> List[str]:
    """Resolve a hostname to all its public A-record IPs (private/loopback
    skipped). IP literals are returned as-is when public."""
    try:
        ip_obj = ipaddress.ip_address(host)
        if ip_obj.is_private or ip_obj.is_loopback:
            return []
        return [str(ip_obj)]
    except ValueError:
        pass
    try:
        answers = await resolve_dns_with_fallback(host, 'A', timeout=5)
    except Exception as e:
        logger.warning(f"[SPF] Could not resolve {host}: {e}")
        return []
    ips = []
    for rr in answers:
        try:
            ip_obj = ipaddress.ip_address(str(rr))
        except ValueError:
            continue
        if ip_obj.is_private or ip_obj.is_loopback:
            continue
        ips.append(str(ip_obj))
    return ips


async def get_spf_source_ips() -> List[Dict[str, str]]:
    """
    Resolve the enabled SPF check sources (server IP / transports /
    relayhosts / manual hosts) into a deduplicated list of {ip, source}.
    A failure in one source never aborts the others.

    Batch callers checking many domains should call this once and pass the
    result to check_spf_record / check_domain_dns.
    """
    entries: List[Dict[str, str]] = []
    seen = set()

    def add(ip, source):
        if ip and ip not in seen:
            seen.add(ip)
            entries.append({'ip': ip, 'source': source})

    if settings.domain_spf_source_server_ip:
        server_ip = get_cached_server_ip()
        if not server_ip:
            server_ip = await init_server_ip()
        add(server_ip, 'auto-detected')

    if settings.domain_spf_source_transports or settings.domain_spf_source_relayhosts:
        from app.scheduler import parse_nexthop_host
        if settings.domain_spf_source_transports:
            try:
                transports = await mailcow_api.get_transports()
            except Exception as e:
                logger.warning(f"[SPF] Failed to fetch transports: {e}")
                transports = []
            for t in transports:
                if str(t.get('active', '0')) != '1':
                    continue
                host = parse_nexthop_host(t.get('nexthop') or '')
                if not host:
                    continue
                for ip in await _resolve_public_host_ips(host):
                    add(ip, 'transport')
        if settings.domain_spf_source_relayhosts:
            try:
                relayhosts = await mailcow_api.get_relayhosts()
            except Exception as e:
                logger.warning(f"[SPF] Failed to fetch relayhosts: {e}")
                relayhosts = []
            for r in relayhosts:
                if str(r.get('active', '0')) != '1':
                    continue
                host = parse_nexthop_host(r.get('hostname') or '')
                if not host:
                    continue
                for ip in await _resolve_public_host_ips(host):
                    add(ip, 'relayhost')

    for entry in settings.domain_spf_source_manual_hosts_list:
        try:
            # Literals are checked as given (the operator asked for them)
            ipaddress.ip_address(entry)
            add(entry, 'configured')
            continue
        except ValueError:
            pass
        for ip in await _resolve_public_host_ips(entry):
            add(ip, 'configured')

    return entries


DMARC_HISTORY_DAYS = 30
DMARC_HISTORY_MAX_IPS = 20
DMARC_HISTORY_STALE_DAYS = 7


def get_recent_dmarc_passing_source_ips(domain: str, days: int = DMARC_HISTORY_DAYS,
                                        limit: int = DMARC_HISTORY_MAX_IPS) -> Dict[str, Any]:
    """
    Distinct source IPs that recently delivered mail for `domain` with a
    passing policy-evaluated SPF result, per imported DMARC aggregate reports.
    Also reports data freshness so the caller can warn when the source has
    nothing to contribute (no reports) or its data may be outdated.

    Sync DB work: event-loop callers must wrap this in asyncio.to_thread.
    """
    from app.database import get_db_context
    try:
        with get_db_context() as db:
            newest_end_date = db.query(func.max(DMARCReport.end_date)).filter(
                DMARCReport.domain == domain
            ).scalar()
            cutoff = int((datetime.now(timezone.utc) - timedelta(days=days)).timestamp())
            rows = db.query(DMARCRecord.source_ip).join(
                DMARCReport, DMARCRecord.dmarc_report_id == DMARCReport.id
            ).filter(
                DMARCReport.domain == domain,
                DMARCReport.begin_date >= cutoff,
                DMARCRecord.spf_result == 'pass'
            ).distinct().limit(limit).all()
    except Exception as e:
        logger.warning(f"[SPF] Error querying DMARC history for {domain}: {e}")
        return {'ips': [], 'reports_found': False, 'newest_report_age_days': None}

    age_days = None
    if newest_end_date:
        age_days = (datetime.now(timezone.utc).timestamp() - newest_end_date) / 86400
    return {
        'ips': [row[0] for row in rows],
        'reports_found': newest_end_date is not None,
        'newest_report_age_days': age_days
    }


def dmarc_history_notes(dmarc_data: Dict[str, Any]) -> List[str]:
    """Informational freshness notes for the DMARC-history SPF source.
    Purely additive: never influences the authorization verdict."""
    notes = []
    if not dmarc_data.get('reports_found'):
        notes.append('DMARC history source is enabled but no reports are available yet')
    else:
        age = dmarc_data.get('newest_report_age_days')
        if age is not None and age > DMARC_HISTORY_STALE_DAYS:
            notes.append(
                f'DMARC history source: newest report for this domain is {int(age)} days old '
                '- data may not reflect current sending activity'
            )
    return notes


async def check_spf_record(domain: str, spf_source_ips: Optional[List[Dict[str, str]]] = None) -> Dict[str, Any]:
    """
    Check SPF record for a domain with full validation.
    spf_source_ips: pre-resolved sources from get_spf_source_ips();
    resolved here when None.
    """
    try:
        answers = await resolve_dns_with_fallback(domain, 'TXT', timeout=5)
        
        spf_records = []
        for rdata in answers:
            txt_data = b''.join(rdata.strings).decode('utf-8')
            if txt_data.startswith('v=spf1'):
                spf_records.append(txt_data)
        
        if len(spf_records) > 1:
            return {
                'status': 'error',
                'message': f'Multiple SPF records found ({len(spf_records)}). Only one is allowed',
                'record': '; '.join(spf_records),
                'has_strict_all': False,
                'includes_mx': False,
                'includes': [],
                'warnings': ['Multiple SPF records invalidate ALL records']
            }
        
        if not spf_records:
            return {
                'status': 'error',
                'message': 'SPF record not found',
                'record': None,
                'has_strict_all': False,
                'includes_mx': False,
                'includes': []
            }
        
        spf_record = spf_records[0]
        
        if not spf_record.startswith('v=spf1 ') and spf_record != 'v=spf1':
            return {
                'status': 'error',
                'message': 'Invalid SPF syntax - must start with "v=spf1 " (with space)',
                'record': spf_record,
                'has_strict_all': False,
                'includes_mx': False,
                'includes': []
            }
        
        parts = spf_record.split()
        mechanisms = parts[1:] if len(parts) > 1 else []
        
        valid_prefixes = ['ip4:', 'ip6:', 'a', 'mx', 'include:', 'exists:', 'redirect', 'all']
        invalid_mechanisms = []
        
        for mechanism in mechanisms:
            clean_mech = mechanism.lstrip('+-~?')
            is_valid = any(clean_mech == prefix or clean_mech.startswith(prefix) for prefix in valid_prefixes)
            if not is_valid:
                invalid_mechanisms.append(mechanism)
        
        if invalid_mechanisms:
            return {
                'status': 'error',
                'message': f'Invalid SPF mechanisms: {", ".join(invalid_mechanisms)}',
                'record': spf_record,
                'has_strict_all': False,
                'includes_mx': False,
                'includes': []
            }
        
        spf_lower = spf_record.lower()
        has_strict_all = '-all' in spf_lower
        has_soft_fail = '~all' in spf_lower
        has_neutral = '?all' in spf_lower
        has_pass_all = '+all' in spf_lower or ' all' in spf_lower
        
        has_redirect = any(m.startswith('redirect=') for m in mechanisms)
        
        if not (has_strict_all or has_soft_fail or has_neutral or has_pass_all or has_redirect):
            return {
                'status': 'error',
                'message': 'SPF record missing "all" mechanism',
                'record': spf_record,
                'has_strict_all': False,
                'includes_mx': False,
                'includes': [],
                'warnings': ['SPF should end with -all or ~all']
            }
        
        includes_mx = any(m.lstrip('+-~?') in ['mx'] or m.lstrip('+-~?').startswith('mx:') for m in mechanisms)
        
        includes = [m.replace('include:', '') for m in mechanisms if m.startswith('include:')]
        
        dns_lookup_count = await count_spf_dns_lookups(domain, spf_record, None)

        if spf_source_ips is None:
            spf_source_ips = await get_spf_source_ips()

        history_notes: List[str] = []
        if settings.domain_spf_source_dmarc_history:
            dmarc_data = await asyncio.to_thread(get_recent_dmarc_passing_source_ips, domain)
            already = {e['ip'] for e in spf_source_ips}
            extra = [{'ip': ip, 'source': 'dmarc-history'}
                     for ip in dmarc_data['ips'] if ip not in already]
            if extra:
                # New list: batch callers share spf_source_ips across domains
                spf_source_ips = spf_source_ips + extra
            history_notes = dmarc_history_notes(dmarc_data)

        server_authorized = False
        authorization_method = None
        unauthorized_ips = []
        checked_ips = []

        if spf_source_ips:
            methods = []
            for source_entry in spf_source_ips:
                check_ip = source_entry['ip']
                ip_authorized, ip_method = await check_ip_in_spf(domain, check_ip, spf_record, None)
                checked_ips.append({
                    'ip': check_ip,
                    'source': source_entry['source'],
                    'authorized': ip_authorized
                })
                if ip_authorized:
                    if ip_method:
                        methods.append(ip_method)
                else:
                    unauthorized_ips.append(check_ip)
            server_authorized = not unauthorized_ips
            if server_authorized and methods:
                # Deduplicate while preserving order
                authorization_method = ', '.join(dict.fromkeys(methods))

        unauthorized_label = ', '.join(unauthorized_ips)
        ip_word = 'IPs' if len(unauthorized_ips) > 1 else 'IP'

        warnings = []
        
        if dns_lookup_count > 10:
            status = 'error'
            message = f'SPF has too many DNS lookups ({dns_lookup_count}). Maximum is 10'
            warnings = [f'SPF record exceeds the 10 DNS lookup limit with {dns_lookup_count} lookups', 'This will cause SPF validation to fail']
        elif has_pass_all:
            status = 'error'
            message = 'SPF uses +all (allows any server). This provides no protection!'
            warnings = ['+all allows anyone to send email as your domain']
        elif not server_authorized and checked_ips:
            status = 'error'
            message = f'Server {ip_word} {unauthorized_label} {"are" if len(unauthorized_ips) > 1 else "is"} NOT authorized in SPF record'
            warnings = ['Mail server IP not found in SPF record']
        elif has_strict_all:
            status = 'success'
            message = f'SPF configured correctly with strict -all policy{f". Server IP authorized via {authorization_method}" if server_authorized else ""}'
            warnings = []
        elif has_soft_fail:
            status = 'success'
            message = f'SPF uses ~all (soft fail){f". Server IP authorized via {authorization_method}" if server_authorized else ""}. Consider using -all for stricter policy'
            warnings = []
        elif has_neutral:
            status = 'warning'
            message = 'SPF uses ?all (neutral). Consider using -all for stricter policy'
            warnings = ['Using ?all provides minimal protection']
        elif has_redirect:
            redirect_domain = next((m.split('=', 1)[1] for m in mechanisms if m.startswith('redirect=')), 'unknown')
            
            if server_authorized:
                status = 'success'
                message = f'SPF redirects to {redirect_domain} (Server authorized via {authorization_method})'
                warnings = []
            else:
                status = 'warning'
                message = f'SPF redirects to {redirect_domain}'
                warnings = [f'Server {ip_word} {unauthorized_label} not authorized by redirected SPF'] if unauthorized_ips else []
        else:
            status = 'success'
            message = 'SPF record found'
            warnings = []

        if history_notes:
            warnings = warnings + history_notes

        return {
            'status': status,
            'message': message,
            'record': spf_record,
            'has_strict_all': has_strict_all,
            'includes_mx': includes_mx,
            'includes': includes,
            'warnings': warnings,
            'dns_lookups': dns_lookup_count,
            # Cached rows written before this field existed lack the key
            'checked_ips': checked_ips
        }
        
    except dns.resolver.NXDOMAIN:
        return {
            'status': 'error',
            'message': 'Domain does not exist',
            'record': None,
            'has_strict_all': False,
            'includes_mx': False,
            'includes': []
        }
    except dns.resolver.NoAnswer:
        return {
            'status': 'error',
            'message': 'No TXT records found',
            'record': None,
            'has_strict_all': False,
            'includes_mx': False,
            'includes': []
        }
    except Exception as e:
        logger.error(f"Error checking SPF for {domain}: {e}")
        return {
            'status': 'error',
            'message': 'Failed to check SPF. Check the application logs.',
            'record': None,
            'has_strict_all': False,
            'includes_mx': False,
            'includes': []
        }


async def check_ip_in_spf(domain: str, ip_to_check: str, spf_record: str, resolver=None, visited_domains: set = None, depth: int = 0) -> tuple:
    """
    Check if IP (IPv4 or IPv6) is authorized in SPF record recursively
    Returns: (authorized: bool, method: str or None)
    """
    if depth > 10:
        return False, None

    if visited_domains is None:
        visited_domains = set()

    if domain in visited_domains:
        return False, None

    visited_domains.add(domain)

    try:
        target_ip = ipaddress.ip_address(ip_to_check)
    except ValueError:
        logger.warning(f"check_ip_in_spf: '{ip_to_check}' is not a valid IP address")
        return False, None

    # IPv6 targets must be compared against AAAA records for a/mx mechanisms
    address_record_type = 'AAAA' if target_ip.version == 6 else 'A'

    parts = spf_record.split()

    for part in parts:
        clean_part = part.lstrip('+-~?')

        if clean_part.startswith('ip4:') or clean_part.startswith('ip6:'):
            mech_prefix = clean_part[:4]   # 'ip4:' / 'ip6:'
            ip_spec = clean_part[4:]
            try:
                # ip_network handles both plain addresses (/32 or /128) and CIDR
                network = ipaddress.ip_network(ip_spec, strict=False)
                if target_ip.version == network.version and target_ip in network:
                    return True, f'{mech_prefix}{ip_spec}'
            except Exception:
                pass

        elif clean_part in ['a'] or clean_part.startswith('a:'):
            check_domain = domain if clean_part == 'a' else clean_part.split(':', 1)[1]
            try:
                a_records = await resolve_dns_with_fallback(check_domain, address_record_type, timeout=5)
                for rdata in a_records:
                    try:
                        if ipaddress.ip_address(str(rdata)) == target_ip:
                            return True, f'a:{check_domain}' if clean_part.startswith('a:') else 'a'
                    except ValueError:
                        continue
            except Exception:
                pass

        elif clean_part in ['mx'] or clean_part.startswith('mx:'):
            check_domain = domain if clean_part == 'mx' else clean_part.split(':', 1)[1]
            try:
                mx_records = await resolve_dns_with_fallback(check_domain, 'MX', timeout=5)
                for mx in mx_records:
                    try:
                        mx_a_records = await resolve_dns_with_fallback(str(mx.exchange), address_record_type, timeout=5)
                        for rdata in mx_a_records:
                            try:
                                if ipaddress.ip_address(str(rdata)) == target_ip:
                                    return True, f'mx:{check_domain}' if clean_part.startswith('mx:') else 'mx'
                            except ValueError:
                                continue
                    except Exception:
                        pass
            except Exception:
                pass
        
        elif clean_part.startswith('include:'):
            include_domain = clean_part.replace('include:', '')
            try:
                include_answers = await resolve_dns_with_fallback(include_domain, 'TXT', timeout=5)
                for rdata in include_answers:
                    include_spf = b''.join(rdata.strings).decode('utf-8')
                    if include_spf.startswith('v=spf1'):
                        authorized, method = await check_ip_in_spf(
                            include_domain, 
                            ip_to_check, 
                            include_spf, 
                            resolver, 
                            visited_domains.copy(),
                            depth + 1
                        )
                        if authorized:
                            return True, f'include:{include_domain} ({method})'
            except Exception:
                pass
        
        elif clean_part.startswith('redirect='):
            redirect_domain = clean_part.replace('redirect=', '')
            try:
                redirect_answers = await resolve_dns_with_fallback(redirect_domain, 'TXT', timeout=5)
                for rdata in redirect_answers:
                    redirect_spf = b''.join(rdata.strings).decode('utf-8')
                    if redirect_spf.startswith('v=spf1'):
                        authorized, method = await check_ip_in_spf(
                            redirect_domain, 
                            ip_to_check, 
                            redirect_spf, 
                            None,  # resolver parameter no longer needed
                            visited_domains.copy(),
                            depth + 1
                        )
                        if authorized:
                            return True, f'redirect:{redirect_domain} ({method})'
            except Exception:
                pass
    
    return False, None


async def count_spf_dns_lookups(domain: str, spf_record: str, resolver=None, visited_domains: set = None, depth: int = 0) -> int:
    """
    Count DNS lookups in SPF record recursively
    SPF limit is 10 DNS lookups
    """
    if depth > 10:
        return 999
    
    if visited_domains is None:
        visited_domains = set()
    
    if domain in visited_domains:
        return 0
    
    visited_domains.add(domain)
    
    parts = spf_record.split()
    lookup_count = 0
    
    for part in parts:
        clean_part = part.lstrip('+-~?')
        
        if clean_part.startswith('include:'):
            lookup_count += 1
            include_domain = clean_part.replace('include:', '')
            try:
                include_answers = await resolve_dns_with_fallback(include_domain, 'TXT', timeout=5)
                for rdata in include_answers:
                    include_spf = b''.join(rdata.strings).decode('utf-8')
                    if include_spf.startswith('v=spf1'):
                        nested_count = await count_spf_dns_lookups(
                            include_domain,
                            include_spf,
                            resolver,
                            visited_domains.copy(),
                            depth + 1
                        )
                        lookup_count += nested_count
                        break
            except Exception:
                pass
        
        elif clean_part in ['a'] or clean_part.startswith('a:'):
            lookup_count += 1
        
        elif clean_part in ['mx'] or clean_part.startswith('mx:'):
            lookup_count += 1
        
        elif clean_part.startswith('exists:'):
            lookup_count += 1
        
        elif clean_part.startswith('redirect='):
            lookup_count += 1
    
    return lookup_count


def parse_dkim_parameters(dkim_record: str) -> Dict[str, Any]:
    """
    Parse and validate DKIM record parameters
    
    Args:
        dkim_record: DKIM TXT record string
        
    Returns:
        Dictionary with parameter validation results
    """
    issues = []
    info = []
    
    params = normalize_dkim_record(dkim_record)

    if 'p' in params and params['p'] == '':
        issues.append({
            'level': 'error',
            'message': 'DKIM key is revoked (p= is empty)',
            'description': 'This DKIM record has been intentionally disabled'
        })
    
    if 't' in params:
        flags = params['t']
        if 'y' in flags:
            issues.append({
                'level': 'critical',
                'message': 'DKIM is in TESTING mode (t=y)',
                'description': 'Emails will pass validation even with invalid signatures. Remove t=y for production!'
            })
        if 's' in flags:
            info.append({
                'level': 'info',
                'message': 'DKIM uses strict subdomain mode (t=s)',
                'description': 'Only the main domain can send emails. Subdomains like mail.example.com will fail DKIM validation'
            })
    
    if 'h' in params:
        hash_algo = params['h'].lower()
        if hash_algo == 'sha1':
            issues.append({
                'level': 'warning',
                'message': 'DKIM uses SHA1 hash algorithm (h=sha1)',
                'description': 'SHA1 is deprecated and insecure. Upgrade to SHA256 (h=sha256)'
            })
    
    if 'k' in params:
        key_type = params['k'].lower()
        if key_type not in ['rsa', 'ed25519']:
            issues.append({
                'level': 'warning',
                'message': f'Unknown key type: {key_type}',
                'description': 'Expected rsa or ed25519'
            })
    
    return {
        'has_issues': len(issues) > 0,
        'issues': issues,
        'info': info,
        'parameters': params
    }


def normalize_dkim_record(record: str) -> Dict[str, str]:
    """Parse DKIM record into normalized parameter dictionary"""
    params = {}
    for part in record.split(';'):
        part = part.strip()
        if not part:
            continue
        if '=' in part:
            key, value = part.split('=', 1)
            params[key.strip()] = value.strip()
    return params


# mailcow signs outgoing mail with rsa-sha256
DKIM_SIGNING_HASH = 'sha256'


def compare_dkim_records(expected: str, actual: str) -> Dict[str, List[str]]:
    """
    Compare mailcow's DKIM record with the published one, tag by tag.

    DNS providers often reorder tags, add h=sha256 or drop t=s. Only a
    different key, key type or a hash list without sha256 stops receivers
    from verifying mailcow's signatures; other tags only narrow the policy.

    Returns:
        Dictionary with 'mismatches' (verification breaks) and
        'differences' (tags that differ but still verify)
    """
    expected_params = normalize_dkim_record(expected)
    actual_params = normalize_dkim_record(actual)
    mismatches = []
    differences = []

    # Base64 in p= may contain folding whitespace (RFC 6376 section 3.6.1)
    expected_key = re.sub(r'\s+', '', expected_params.get('p', ''))
    actual_key = re.sub(r'\s+', '', actual_params.get('p', ''))
    if expected_key != actual_key:
        mismatches.append('Public key (p=) does not match the key in mailcow')

    actual_version = actual_params.get('v', 'DKIM1')
    if actual_version != 'DKIM1':
        mismatches.append(f'Unsupported version (v={actual_version})')

    expected_type = expected_params.get('k', 'rsa').lower()
    actual_type = actual_params.get('k', 'rsa').lower()
    if expected_type != actual_type:
        mismatches.append(f'Key type k={actual_type} does not match mailcow (k={expected_type})')

    reported_tags = {'v', 'p', 'k'}
    if 'h' in actual_params:
        hashes = [h.strip().lower() for h in actual_params['h'].split(':')]
        if DKIM_SIGNING_HASH not in hashes:
            mismatches.append(
                f'h={actual_params["h"]} does not allow {DKIM_SIGNING_HASH}, which mailcow signs with'
            )
            reported_tags.add('h')

    for tag in sorted((expected_params.keys() | actual_params.keys()) - reported_tags):
        expected_value = expected_params.get(tag)
        actual_value = actual_params.get(tag)
        if expected_value == actual_value:
            continue
        if actual_value is None:
            differences.append(f'{tag}={expected_value} from the mailcow record is missing')
        elif expected_value is None:
            differences.append(f'{tag}={actual_value} is not in the mailcow record')
        else:
            differences.append(f'{tag}={actual_value} differs from mailcow ({tag}={expected_value})')

    return {'mismatches': mismatches, 'differences': differences}


async def check_dkim_record(domain: str) -> Dict[str, Any]:
    """
    Check DKIM record for a domain
    
    Args:
        domain: Domain name to check
        
    Returns:
        Dictionary with DKIM check results
    """
    try:
        # Get DKIM configuration from mailcow using mailcow_api
        dkim_config = await mailcow_api.get_dkim(domain)
        
        if dkim_config is None:
            logger.warning(f"DKIM not configured in mailcow for {domain}")
            return {
                'status': 'error',
                'message': 'DKIM not configured in mailcow',
                'selector': None,
                'expected_record': None,
                'actual_record': None,
                'match': False,
                'warnings': [],
                'info': [],
                'parameters': {}
            }
        
        # Validate required fields
        if not isinstance(dkim_config, dict):
            logger.error(f"DKIM config is not a dict for {domain}: {type(dkim_config)}")
            return {
                'status': 'error',
                'message': 'Invalid DKIM configuration format',
                'selector': None,
                'expected_record': None,
                'actual_record': None,
                'match': False,
                'warnings': [],
                'info': [],
                'parameters': {}
            }
        
        selector = dkim_config.get('dkim_selector', 'dkim')
        expected_value = dkim_config.get('dkim_txt', '')
        
        if not expected_value:
            logger.warning(f"DKIM record is empty in mailcow for {domain}")
            return {
                'status': 'error',
                'message': 'DKIM record is empty in mailcow configuration',
                'selector': selector,
                'expected_record': None,
                'actual_record': None,
                'match': False,
                'warnings': [],
                'info': [],
                'parameters': {}
            }
        
        # Construct DKIM domain
        dkim_domain = f"{selector}._domainkey.{domain}"
        
        # Query DKIM TXT record
        try:
            answers = await resolve_dns_with_fallback(dkim_domain, 'TXT', timeout=5)
            
            # Get actual DKIM record
            actual_record = ''
            for rdata in answers:
                actual_record = b''.join(rdata.strings).decode('utf-8')
                break
            
            comparison = compare_dkim_records(expected_value, actual_record)
            match = not comparison['mismatches']

            dkim_params = parse_dkim_parameters(actual_record)

            warnings = [f"❌ {m}" for m in comparison['mismatches']]
            warnings += [f"⚠️ {d}" for d in comparison['differences']]
            info_messages = []
            critical_issues = []

            for issue in dkim_params['issues']:
                if issue['level'] == 'critical':
                    critical_issues.append(f"{issue['message']} - {issue['description']}")
                elif issue['level'] == 'error':
                    warnings.append(f"❌ {issue['message']}")
                elif issue['level'] == 'warning':
                    warnings.append(f"⚠️ {issue['message']}")
            
            for item in dkim_params['info']:
                info_messages.append(item['message'])
            
            if critical_issues:
                status = 'error'
                message = critical_issues[0]
            elif not match:
                status = 'error'
                message = 'DKIM record mismatch'
            elif warnings:
                status = 'warning'
                message = 'DKIM configured but has warnings'
            else:
                status = 'success'
                message = 'DKIM configured correctly'
            
            if match:
                logger.info(f"DKIM check passed for {domain}")
            else:
                logger.warning(f"DKIM mismatch for {domain}")
            
            return {
                'status': status,
                'message': message,
                'selector': selector,
                'dkim_domain': dkim_domain,
                'expected_record': expected_value,
                'actual_record': actual_record,
                'match': match,
                'warnings': warnings,
                'info': info_messages,
                'parameters': dkim_params['parameters']
            }
            
        except dns.resolver.NXDOMAIN:
            logger.warning(f"DKIM record not found for {domain} at {dkim_domain}")
            return {
                'status': 'error',
                'message': f'DKIM record not found at {dkim_domain}',
                'selector': selector,
                'dkim_domain': dkim_domain,
                'expected_record': expected_value,
                'actual_record': None,
                'match': False
            ,
                'warnings': [],
                'info': [],
                'parameters': {}
            }
        except dns.resolver.NoAnswer:
            logger.warning(f"No TXT record at {dkim_domain} for {domain}")
            return {
                'status': 'error',
                'message': f'No TXT record at {dkim_domain}',
                'selector': selector,
                'dkim_domain': dkim_domain,
                'expected_record': expected_value,
                'actual_record': None,
                'match': False
            ,
                'warnings': [],
                'info': [],
                'parameters': {}
            }
        except dns.exception.Timeout:
            logger.error(f"DNS timeout checking DKIM for {domain}")
            return {
                'status': 'error',
                'message': 'DNS query timeout',
                'selector': selector,
                'dkim_domain': dkim_domain,
                'expected_record': expected_value,
                'actual_record': None,
                'match': False,
                'warnings': [],
                'info': [],
                'parameters': {}
            }
            
    except Exception as e:
        logger.error(f"Unexpected error checking DKIM for {domain}: {type(e).__name__} - {str(e)}")
        return {
            'status': 'error',
            'message': 'Failed to check DKIM. Check the application logs.',
            'selector': None,
            'expected_record': None,
            'actual_record': None,
            'match': False
        ,
            'warnings': [],
            'info': [],
            'parameters': {}
        }


def parse_dmarc_record_tags(record_str: str) -> Dict[str, Any]:
    """
    Parse DMARC TXT record string into structured settings (RFC 7489 tags).
    Returns a dict with human-readable keys; only includes tags that are present.
    """
    if not record_str or not record_str.strip().startswith('v=DMARC1'):
        return {}
    settings = {}
    # Split by semicolon; each part is tag=value (value may contain commas for rua/ruf)
    for part in record_str.split(';'):
        part = part.strip()
        if not part or '=' not in part:
            continue
        tag, _, value = part.partition('=')
        tag = tag.strip().lower()
        value = value.strip()
        if not value:
            continue
        if tag == 'p':
            settings['policy'] = value.lower()
        elif tag == 'sp':
            settings['subdomain_policy'] = value.lower()
        elif tag == 'rua':
            # Comma-separated list of URIs (e.g. mailto:dmarc@example.com)
            settings['aggregate_report_uris'] = [u.strip() for u in value.split(',') if u.strip()]
        elif tag == 'ruf':
            settings['forensic_report_uris'] = [u.strip() for u in value.split(',') if u.strip()]
        elif tag == 'adkim':
            settings['dkim_alignment'] = value.lower()
        elif tag == 'aspf':
            settings['spf_alignment'] = value.lower()
        elif tag == 'pct':
            try:
                settings['percentage'] = int(value)
            except ValueError:
                settings['percentage'] = value
        elif tag == 'fo':
            settings['failure_reporting_options'] = value.lower()
    return settings


async def check_dmarc_record(domain: str) -> Dict[str, Any]:
    """
    Check DMARC record for a domain
    
    Args:
        domain: Domain name to check
        
    Returns:
        Dictionary with DMARC check results (status, message, record, policy, is_strong, warnings, settings)
    """
    try:
        dmarc_domain = f"_dmarc.{domain}"
        
        # Query DMARC TXT record
        answers = await resolve_dns_with_fallback(dmarc_domain, 'TXT', timeout=5)
        
        # Get DMARC record
        dmarc_record = None
        for rdata in answers:
            txt_data = b''.join(rdata.strings).decode('utf-8')
            if txt_data.startswith('v=DMARC1'):
                dmarc_record = txt_data
                break
        
        if not dmarc_record:
            return {
                'status': 'error',
                'message': 'DMARC record not found',
                'record': None,
                'policy': None,
                'is_strong': False,
                'warnings': ['Add a DMARC record with at least "quarantine" policy'],
                'settings': {}
            }
        
        # Extract policy
        policy_match = re.search(r'p=(none|quarantine|reject)', dmarc_record)
        policy = policy_match.group(1) if policy_match else 'unknown'
        
        # Parse all tags into settings
        settings = parse_dmarc_record_tags(dmarc_record)
        
        # Check if policy is strong enough
        is_strong = policy in ['quarantine', 'reject']
        
        status = 'success' if is_strong else 'warning'
        message = f'DMARC configured with {policy} policy'
        
        if not is_strong:
            message = f'DMARC policy is too weak ({policy})'
        
        warnings = []
        if not is_strong:
            warnings.append('Consider using "quarantine" or "reject" policy for better email protection')
        
        return {
            'status': status,
            'message': message,
            'record': dmarc_record,
            'policy': policy,
            'is_strong': is_strong,
            'warnings': warnings,
            'settings': settings
        }
        
    except dns.resolver.NXDOMAIN:
        return {
            'status': 'error',
            'message': 'DMARC record not found',
            'record': None,
            'policy': None,
            'is_strong': False,
            'warnings': ['Add a DMARC record with at least "quarantine" policy'],
            'settings': {}
        }
    except dns.resolver.NoAnswer:
        return {
            'status': 'error',
            'message': 'No DMARC record configured',
            'record': None,
            'policy': None,
            'is_strong': False,
            'warnings': ['Add a DMARC record with at least "quarantine" policy'],
            'settings': {}
        }
    except Exception as e:
        logger.error(f"Error checking DMARC for {domain}: {e}")
        return {
            'status': 'error',
            'message': 'Failed to check DMARC. Check the application logs.',
            'record': None,
            'policy': None,
            'is_strong': False,
            'warnings': [],
            'settings': {}
        }


async def resolve_dnssec_with_fallback(query: str, record_type: str = 'A', timeout: int = 5,
                                       checking_disabled: bool = False):
    """DNSSEC-aware lookup that reports the resolver's AD flag.

    Kept module-level, like resolve_dns_with_fallback, so tests can inject a
    fake resolver. See app.services.dns_resolver.resolve_dnssec.
    """
    from app.services.dns_resolver import resolve_dnssec
    return await resolve_dnssec(query, record_type, timeout, checking_disabled)


async def _fetch_mx_certificate(host: str) -> bytes:
    """DER certificate the MX host presents over STARTTLS on port 25.

    Module-level so tests can inject a fake instead of connecting.
    """
    from app.services import dane
    return await dane.fetch_smtp_certificate(host)


async def check_dnssec_record(domain: str) -> Dict[str, Any]:
    """
    Check whether the domain is DNSSEC signed and validates.

    DNSSEC protects every record of the domain (MX, SPF, DKIM, DMARC) from
    spoofing and is a prerequisite for DANE. The validating public resolvers
    used for all DNS checks set the AD flag on a validated answer.

    Returns the same shape as the other checks (status/message/record/warnings).
    """
    def result(status, message, validated, warnings=None, info=None):
        return {
            'status': status,
            'message': message,
            'record': None,
            'validated': validated,
            'warnings': warnings or [],
            'info': info or [],
        }

    try:
        try:
            answer = await resolve_dnssec_with_fallback(domain, 'SOA', timeout=5)
        except Exception as e:
            logger.error("Could not check DNSSEC for %s: %s", domain, e)
            return result('unknown', 'Could not check DNSSEC. Check the application logs.', None)

        if answer.rcode == dns.rcode.SERVFAIL:
            # Validating resolvers answer SERVFAIL for a broken signature. The
            # same query with checking disabled succeeds when DNSSEC is the cause.
            try:
                unchecked = await resolve_dnssec_with_fallback(domain, 'SOA', timeout=5,
                                                               checking_disabled=True)
            except Exception:
                unchecked = None
            if unchecked is not None and unchecked.rcode in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
                return result(
                    'error',
                    'DNSSEC validation fails - resolvers that check signatures cannot resolve this domain',
                    False,
                    warnings=['Mail to and from this domain can fail. Check that the DS record at your '
                              'registrar matches the keys your DNS provider publishes.'],
                )
            return result('unknown', 'DNS lookup failed for this domain', None)

        if answer.rcode != dns.rcode.NOERROR:
            return result('unknown', 'Domain not found in DNS - cannot check DNSSEC', None)

        if answer.authenticated:
            return result('success', 'DNSSEC signed and validated', True)

        # Not validated. Keys without a DS record at the registrar are a
        # common half-finished setup worth naming.
        has_keys = False
        try:
            keys = await resolve_dnssec_with_fallback(domain, 'DNSKEY', timeout=5)
            has_keys = bool(keys.records)
        except Exception:
            pass
        if has_keys:
            return result(
                'warning',
                'DNSSEC keys are published but not validated - the DS record is missing at the registrar',
                False,
                info=['Publish the DS record at your registrar to complete the DNSSEC setup.'],
            )
        return result(
            'warning',
            'DNSSEC not enabled for this domain',
            False,
            info=['DNSSEC protects your DNS records from spoofing and is required for DANE. '
                  'Enable it at your DNS provider, then publish the DS record at your registrar.'],
        )

    except Exception as e:
        logger.error(f"Error checking DNSSEC for {domain}: {e}")
        return result('unknown', 'Could not check DNSSEC. Check the application logs.', None)


async def _host_address_validated(host: str) -> Optional[bool]:
    """Whether the MX host's address records are DNSSEC validated.

    RFC 7672: senders only use the TLSA records of an MX host whose address
    lookup is secure. None when the lookup failed.
    """
    for rtype in ('A', 'AAAA'):
        try:
            answer = await resolve_dnssec_with_fallback(host, rtype, timeout=5)
        except Exception:
            return None
        if answer.rcode != dns.rcode.NOERROR:
            return None
        if answer.records:
            return answer.authenticated
    return None


async def check_tlsa_record(domain: str) -> Dict[str, Any]:
    """
    Check DANE for a domain's mail servers: TLSA records, their DNSSEC
    validation, and whether they match the certificate each MX presents.

    DANE for SMTP publishes TLSA records under the MX hostname, not the domain
    itself: _25._tcp.<mx-host>. So we resolve MX first, then look up each host.
    Senders only use the records when the MX records, the MX host's address
    and the TLSA records are all DNSSEC validated (RFC 7672).

    Returns the same shape as the other checks (status/message/record/warnings).
    """
    from app.services import dane

    try:
        # 1. Which mail servers does this domain use?
        null_mx = False
        mx_validated = False
        mx_lookup_failed = False
        hosts = set()
        try:
            mx_answer = await resolve_dnssec_with_fallback(domain, 'MX', timeout=5)
            if mx_answer.rcode not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
                mx_lookup_failed = True
            elif mx_answer.rcode == dns.rcode.NOERROR:
                mx_validated = mx_answer.authenticated
                for r in mx_answer.records:
                    exchange = str(getattr(r, 'exchange', '') or '').rstrip('.').strip()
                    if not exchange:
                        # RFC 7505 "null MX" (0 .) - the domain accepts no mail at all
                        null_mx = True
                        continue
                    hosts.add(exchange)
        except Exception:
            mx_lookup_failed = True
        mx_hosts = sorted(hosts)

        if not mx_hosts:
            if null_mx:
                message = 'Domain does not accept mail (null MX) - DANE/TLSA does not apply'
            elif mx_lookup_failed:
                # A timeout or SERVFAIL says nothing about the MX records
                message = 'Could not look up MX records - cannot check DANE/TLSA'
            else:
                message = 'No MX records found - cannot check DANE/TLSA'
            return {
                'status': 'unknown',
                'message': message,
                'record': None,
                'records': [],
                'mx_hosts': [],
                'warnings': [],
            }

        # 2. TLSA records under each mail server, and the certificate they pin.
        # Hosts are checked in parallel: an unreachable port 25 costs a timeout.
        async def check_host(host):
            """(records, result) for one MX host; None when the lookup failed."""
            try:
                tlsa_answer = await resolve_dnssec_with_fallback(f"_25._tcp.{host}", 'TLSA', timeout=5)
            except Exception:
                return None
            if tlsa_answer.rcode not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
                return None

            host_records = []
            for rdata in tlsa_answer.records:
                usage = getattr(rdata, 'usage', None)
                selector = getattr(rdata, 'selector', None)
                mtype = getattr(rdata, 'mtype', None)
                cert = getattr(rdata, 'cert', b'')
                cert_hex = cert.hex() if isinstance(cert, (bytes, bytearray)) else str(cert)
                host_records.append({
                    'host': host,
                    'usage': usage,
                    'selector': selector,
                    'matching_type': mtype,
                    'certificate': cert_hex,
                    'record': f"{usage} {selector} {mtype} {cert_hex}",
                })
            if not host_records:
                # No TLSA for this host - normal when DANE is off
                return [], None

            host_result = {
                'host': host,
                'tlsa_validated': tlsa_answer.authenticated,
                'address_validated': await _host_address_validated(host),
                'certificate': 'not_verifiable',
            }
            if any(r['usage'] == dane.USAGE_DANE_EE for r in host_records):
                try:
                    certificate = await _fetch_mx_certificate(host)
                except Exception as e:
                    host_result['certificate'] = 'unreachable'
                    host_result['certificate_error'] = str(e)
                else:
                    host_result['certificate'] = (
                        'match' if any(dane.matches_certificate(r, certificate) for r in host_records)
                        else 'mismatch'
                    )
            return host_records, host_result

        all_records = []
        hosts_with_tlsa = []
        lookup_failed = []
        host_results = []
        outcomes = await asyncio.gather(*(check_host(host) for host in mx_hosts))
        for host, outcome in zip(mx_hosts, outcomes):
            if outcome is None:
                lookup_failed.append(host)
                continue
            host_records, host_result = outcome
            if host_records:
                hosts_with_tlsa.append(host)
                all_records.extend(host_records)
                host_results.append(host_result)

        if not all_records:
            if lookup_failed:
                return {
                    'status': 'unknown',
                    'message': f'Could not look up TLSA records for {", ".join(lookup_failed)}',
                    'record': None,
                    'records': [],
                    'mx_hosts': mx_hosts,
                    'warnings': [],
                }
            return {
                'status': 'warning',
                'message': f'No DANE/TLSA records published for {", ".join(mx_hosts)}',
                'record': None,
                'records': [],
                'mx_hosts': mx_hosts,
                'warnings': [
                    'DANE is optional. If you publish TLSA records, senders can verify your '
                    'TLS certificate through DNSSEC. Requires a DNSSEC-signed zone.'
                ],
            }

        # 3. Assess what was published
        warnings = []
        info = []
        missing = [h for h in mx_hosts if h not in hosts_with_tlsa and h not in lookup_failed]
        if missing:
            warnings.append(
                f'No TLSA record for: {", ".join(missing)}. Every MX host should publish one, '
                'or senders may fail to deliver.'
            )
        if lookup_failed:
            warnings.append(f'Could not look up TLSA records for: {", ".join(lookup_failed)}')
        # 3 1 1 (DANE-EE / SPKI / SHA-256) is the recommended combination for SMTP
        if not any(r['usage'] == 3 and r['selector'] == 1 and r['matching_type'] == 1
                   for r in all_records):
            warnings.append(
                'None of the records use the recommended "3 1 1" combination '
                '(DANE-EE, SPKI, SHA-256), which is what mailcow publishes by default.'
            )

        not_validated = []
        if not mx_validated:
            not_validated.append(f'MX records of {domain}')
        for host_result in host_results:
            if not host_result['tlsa_validated']:
                not_validated.append(f'TLSA record of {host_result["host"]}')
            if host_result['address_validated'] is False:
                not_validated.append(f'address of {host_result["host"]}')
        dane_active = not not_validated
        if not dane_active:
            warnings.append('Not DNSSEC validated: ' + ', '.join(not_validated))

        certificate_lines = {
            'match': 'certificate matches the TLSA record',
            'mismatch': 'certificate does not match the TLSA record',
            'unreachable': 'certificate not compared - could not connect on port 25 from this server',
            'not_verifiable': 'certificate not compared - only DANE-EE (usage 3) records can be checked',
        }
        for host_result in host_results:
            info.append(f'{host_result["host"]}: {certificate_lines[host_result["certificate"]]}')

        mismatched = [r['host'] for r in host_results if r['certificate'] == 'mismatch']
        matched = [r['host'] for r in host_results if r['certificate'] == 'match']

        if mismatched and dane_active:
            status = 'error'
            message = (f'TLSA record does not match the certificate of {", ".join(mismatched)} - '
                       'senders that use DANE will refuse to deliver')
        elif mismatched:
            status = 'warning'
            message = (f'TLSA record does not match the certificate of {", ".join(mismatched)} - '
                       'mail will fail once DNSSEC is enabled')
        elif not dane_active:
            status = 'warning'
            message = 'TLSA records are published but not DNSSEC validated - senders ignore them, so DANE is not active'
        else:
            status = 'success' if not warnings else 'warning'
            if len(matched) == len(host_results):
                message = f'DANE active - TLSA records validated and matching the certificate on {len(matched)} mail server(s)'
            else:
                message = 'DANE active - TLSA records validated, certificate not compared on every mail server'

        return {
            'status': status,
            'message': message,
            # `record` keeps the flat text form so change detection can diff it
            'record': ' | '.join(sorted(r['record'] for r in all_records)),
            'records': all_records,
            'mx_hosts': mx_hosts,
            'hosts': host_results,
            'dane_active': dane_active,
            'certificate_mismatch': mismatched if dane_active else [],
            'warnings': warnings,
            'info': info,
        }

    except Exception as e:
        logger.error(f"Error checking TLSA for {domain}: {e}")
        return {
            'status': 'error',
            'message': 'Failed to check TLSA. Check the application logs.',
            'record': None,
            'records': [],
            'mx_hosts': [],
            'warnings': [],
        }


MTA_STS_POLICY_TIMEOUT = 10          # seconds for the HTTPS policy fetch
MTA_STS_POLICY_MAX_BYTES = 64 * 1024  # RFC 8461 policies are a few lines; cap reads


async def _fetch_mta_sts_policy(domain: str) -> str:
    """Fetch https://mta-sts.<domain>/.well-known/mta-sts.txt.

    Kept as a module-level function so tests can inject a fake fetcher, the
    same way resolve_dns_with_fallback is injected for DNS.

    RFC 8461: the policy host must present a valid certificate and HTTP
    redirects must not be followed.
    """
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    async with httpx.AsyncClient(timeout=MTA_STS_POLICY_TIMEOUT,
                                 follow_redirects=False, verify=True) as client:
        response = await client.get(url)
        response.raise_for_status()
        if len(response.content) > MTA_STS_POLICY_MAX_BYTES:
            raise ValueError("policy file larger than expected")
        return response.text


def _parse_mta_sts_policy(text: str) -> Dict[str, Any]:
    """Parse the key/value policy file. Returns {version, mode, max_age, mx: []}."""
    policy: Dict[str, Any] = {'mx': []}
    for line in text.replace('\r\n', '\n').split('\n'):
        line = line.strip()
        if not line or ':' not in line:
            continue
        key, _, value = line.partition(':')
        key = key.strip().lower()
        value = value.strip()
        if key == 'mx':
            policy['mx'].append(value)
        elif key in ('version', 'mode', 'max_age'):
            policy[key] = value
    return policy


def _mx_matches_policy(mx_host: str, patterns: List[str]) -> bool:
    """RFC 8461 MX matching: exact host, or *.example.com matching one label."""
    host = mx_host.lower().rstrip('.')
    for pattern in patterns:
        pat = pattern.lower().rstrip('.')
        if pat.startswith('*.'):
            suffix = pat[1:]              # ".example.com"
            if host.endswith(suffix) and '.' not in host[:-len(suffix)]:
                return True
        elif host == pat:
            return True
    return False


async def check_mta_sts_record(domain: str) -> Dict[str, Any]:
    """
    Check MTA-STS (RFC 8461) for a domain: the _mta-sts TXT record and the
    policy file it points at, including whether the domain's MX hosts are
    covered by the policy.

    Returns the same shape as the other checks (status/message/record/warnings).
    MTA-STS is optional, so a domain without it is a warning, not an error -
    same convention as TLSA.
    """
    try:
        # 1. The DNS record: exactly one v=STSv1 TXT at _mta-sts.<domain>
        sts_records = []
        try:
            answers = await resolve_dns_with_fallback(f'_mta-sts.{domain}', 'TXT', timeout=5)
            for rdata in answers:
                txt = ''.join(
                    s.decode() if isinstance(s, bytes) else str(s)
                    for s in getattr(rdata, 'strings', [])
                ) or str(rdata).strip('"')
                if txt.lower().startswith('v=stsv1'):
                    sts_records.append(txt)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass
        except Exception as e:
            logger.error("Could not check MTA-STS record for %s: %s", domain, e)
            return {
                'status': 'unknown',
                'message': 'Could not check MTA-STS record. Check the application logs.',
                'record': None,
                'warnings': [],
            }

        if not sts_records:
            return {
                'status': 'warning',
                'message': 'MTA-STS record not published',
                'record': None,
                'warnings': [],
                'info': ['Publish a TXT record at _mta-sts.' + domain +
                         ' and a policy file to let senders require TLS for this domain'],
            }

        if len(sts_records) > 1:
            return {
                'status': 'error',
                'message': f'{len(sts_records)} MTA-STS records published - senders ignore the record unless there is exactly one',
                'record': '; '.join(sts_records),
                'warnings': [],
            }

        record = sts_records[0]
        id_match = re.search(r'id\s*=\s*([^;\s]+)', record)
        policy_id = id_match.group(1) if id_match else None

        # 2. The policy file behind the record
        try:
            policy_text = await _fetch_mta_sts_policy(domain)
        except Exception as e:
            logger.error("Could not fetch MTA-STS policy for %s: %s", domain, e)
            return {
                'status': 'error',
                'message': 'MTA-STS record exists but the policy file could not be fetched.',
                'record': record,
                'warnings': ['Senders that support MTA-STS treat a published record '
                             'with an unreachable policy as a hard failure'],
            }

        policy = _parse_mta_sts_policy(policy_text)
        warnings = []
        info = []
        mode = (policy.get('mode') or '').lower()

        if (policy.get('version') or '').upper() != 'STSV1':
            return {
                'status': 'error',
                'message': 'MTA-STS policy file is missing "version: STSv1"',
                'record': record,
                'warnings': [],
            }
        if mode not in ('enforce', 'testing', 'none'):
            return {
                'status': 'error',
                'message': f'MTA-STS policy has an invalid mode: {policy.get("mode")!r}',
                'record': record,
                'warnings': [],
            }

        info.append(f'Mode: {mode}')
        if policy_id:
            info.append(f'Policy id: {policy_id}')
        if policy.get('max_age'):
            info.append(f'Max age: {policy["max_age"]} seconds')
        if policy['mx']:
            info.append('Policy MX: ' + ', '.join(policy['mx']))

        # 3. Are the domain's actual MX hosts covered by the policy?
        unmatched = []
        try:
            mx_answers = await resolve_dns_with_fallback(domain, 'MX', timeout=5)
            mx_hosts = sorted({
                str(getattr(r, 'exchange', '') or '').rstrip('.').strip()
                for r in mx_answers
            } - {''})
            unmatched = [h for h in mx_hosts if not _mx_matches_policy(h, policy['mx'])]
        except Exception:
            mx_hosts = []   # MX lookup failure is not an MTA-STS problem

        if unmatched:
            missing = ', '.join(unmatched)
            if mode == 'enforce':
                return {
                    'status': 'error',
                    'message': f'MX not covered by the enforced MTA-STS policy: {missing} - senders will refuse to deliver through it',
                    'record': record,
                    'warnings': [],
                    'info': info,
                }
            warnings.append(f'MX not covered by the policy: {missing}')

        if mode == 'enforce':
            status = 'success' if not warnings else 'warning'
            message = 'MTA-STS enforced'
        elif mode == 'testing':
            status = 'warning'
            message = 'MTA-STS policy is in testing mode - failures are reported but delivery is not protected'
        else:
            status = 'warning'
            message = 'MTA-STS policy mode is "none" - the policy is effectively disabled'

        return {
            'status': status,
            'message': message,
            'record': record,
            'warnings': warnings,
            'info': info,
        }

    except Exception as e:
        logger.error(f"Error checking MTA-STS for {domain}: {e}")
        return {
            'status': 'unknown',
            'message': 'MTA-STS check failed. Check the application logs.',
            'record': None,
            'warnings': [],
        }


_TLS_RPT_VERSION = re.compile(r'^v\s*=\s*tlsrptv1\s*(;|$)', re.IGNORECASE)


def parse_tls_rpt_record(record: str) -> Dict[str, Any]:
    """Split a TLS-RPT record (RFC 8460) into its report URIs.

    rua holds a comma-separated list; senders deliver to mailto: and https:
    URIs only, so anything else is returned as unsupported.
    """
    rua = None
    for part in record.split(';'):
        key, sep, value = part.partition('=')
        if sep and key.strip().lower() == 'rua':
            rua = value
            break
    uris = [u.strip() for u in (rua or '').split(',') if u.strip()]
    supported = [u for u in uris if re.match(r'^(mailto:\S+@\S+|https://\S+)$', u, re.IGNORECASE)]
    return {
        'report_uris': supported,
        'unsupported_uris': [u for u in uris if u not in supported],
    }


async def check_tls_rpt_record(domain: str) -> Dict[str, Any]:
    """
    Check the TLS-RPT record (RFC 8460) at _smtp._tls.<domain>: the address
    that sending servers deliver their TLS reports to.

    Returns the same shape as the other checks (status/message/record/warnings)
    plus report_uris. TLS-RPT is optional, so a domain without it is a warning
    whose message carries the "not published" marker used by change detection.
    """
    try:
        records = []
        try:
            answers = await resolve_dns_with_fallback(f'_smtp._tls.{domain}', 'TXT', timeout=5)
            for rdata in answers:
                txt = ''.join(
                    s.decode() if isinstance(s, bytes) else str(s)
                    for s in getattr(rdata, 'strings', [])
                ) or str(rdata).strip('"')
                if _TLS_RPT_VERSION.match(txt.strip()):
                    records.append(txt.strip())
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass

        if not records:
            return {
                'status': 'warning',
                'message': 'TLS-RPT record not published',
                'record': None,
                'report_uris': [],
                'warnings': [],
                'info': [f'Publish a TXT record at _smtp._tls.{domain} with a rua address '
                         'to receive TLS reports from sending servers'],
            }

        if len(records) > 1:
            return {
                'status': 'error',
                'message': f'{len(records)} TLS-RPT records published - senders ignore them unless there is exactly one',
                'record': '; '.join(records),
                'report_uris': [],
                'warnings': [],
            }

        record = records[0]
        parsed = parse_tls_rpt_record(record)
        warnings = [f'Senders only deliver to mailto: and https: addresses, not {uri}'
                    for uri in parsed['unsupported_uris']]

        if not parsed['report_uris']:
            return {
                'status': 'error',
                'message': 'TLS-RPT record has no valid rua address - no reports will be sent',
                'record': record,
                'report_uris': [],
                'warnings': warnings,
            }

        return {
            'status': 'success',
            'message': 'TLS-RPT configured',
            'record': record,
            'report_uris': parsed['report_uris'],
            'warnings': warnings,
        }

    except Exception as e:
        logger.error(f"Error checking TLS-RPT for {domain}: {e}")
        return {
            'status': 'unknown',
            'message': 'Could not check TLS-RPT record. Check the application logs.',
            'record': None,
            'report_uris': [],
            'warnings': [],
        }


async def check_domain_dns(domain: str, spf_source_ips: Optional[List[Dict[str, str]]] = None) -> Dict[str, Any]:
    """
    Check all DNS records (SPF, DKIM, DMARC, DNSSEC, TLSA/DANE, MTA-STS, TLS-RPT) for a domain

    Args:
        domain: Domain name to check
        spf_source_ips: pre-resolved SPF sources (see get_spf_source_ips).
            Batch callers should resolve once and pass them here to avoid
            redundant mailcow API/DNS calls per domain.

    Returns:
        Dictionary with all DNS check results
    """
    try:
        # Run all checks in parallel
        (spf_result, dkim_result, dmarc_result, dnssec_result, tlsa_result, mta_sts_result,
         tls_rpt_result) = await asyncio.gather(
            check_spf_record(domain, spf_source_ips),
            check_dkim_record(domain),
            check_dmarc_record(domain),
            check_dnssec_record(domain),
            check_tlsa_record(domain),
            check_mta_sts_record(domain),
            check_tls_rpt_record(domain)
        )

        return {
            'domain': domain,
            'spf': spf_result,
            'dkim': dkim_result,
            'dmarc': dmarc_result,
            'dnssec': dnssec_result,
            'tlsa': tlsa_result,
            'mta_sts': mta_sts_result,
            'tls_rpt': tls_rpt_result,
            'checked_at': format_datetime_for_api(datetime.now(timezone.utc))
        }
        
    except Exception as e:
        logger.error(f"Error checking DNS for {domain}: {e}")
        return {
            'domain': domain,
            'error': 'Unable to check DNS. Check the application logs.',
            'checked_at': format_datetime_for_api(datetime.now(timezone.utc))
        }


def _build_domain_list_worker(domains):
    """Build detached domain and DNS results in a worker-owned session."""
    with get_db_context() as db:
        # Get last DNS check time FIRST
        last_check = db.query(DomainDNSCheck).filter(
        DomainDNSCheck.is_full_check == True
        ).order_by(
            DomainDNSCheck.checked_at.desc()
        ).first()
        
        if not domains:
            return {
                'domains': [],
                'total': 0,
                'active': 0,
                'last_dns_check': format_datetime_for_api(last_check.checked_at) if (last_check and last_check.checked_at) else None
            }
        
        alias_domain_map = get_alias_domain_map(db)

        result_domains = []
        for domain_data in domains:
            domain_name = domain_data.get('domain_name')
            if not domain_name:
                continue
            
            # Get cached DNS check
            dns_checks = get_cached_dns_check(db, domain_name)

            # Alias domains of this domain, with their own cached checks
            # (issue #92) - they are real sending domains with their own DNS
            alias_entries = [
                {
                    'domain_name': alias_name,
                    'dns_checks': get_cached_dns_check(db, alias_name) or {},
                }
                for alias_name in aliases_of_domain(domain_name, alias_domain_map)
            ]
            
            result_domains.append({
                'domain_name': domain_name,
                'active': domain_data.get('active', 0) == 1,
                'mboxes_in_domain': domain_data.get('mboxes_in_domain', 0),
                'mboxes_left': domain_data.get('mboxes_left', 0),
                'max_num_mboxes_for_domain': domain_data.get('max_num_mboxes_for_domain', 0),
                'aliases_in_domain': domain_data.get('aliases_in_domain', 0),
                'aliases_left': domain_data.get('aliases_left', 0),
                'max_num_aliases_for_domain': domain_data.get('max_num_aliases_for_domain', 0),
                'created': domain_data.get('created'),
                'bytes_total': domain_data.get('bytes_total', 0),
                'msgs_total': domain_data.get('msgs_total', 0),
                'quota_used_in_domain': domain_data.get('quota_used_in_domain', '0'),
                'max_quota_for_domain': domain_data.get('max_quota_for_domain', 0),
                'backupmx': domain_data.get('backupmx', 0) == 1,
                'relay_all_recipients': domain_data.get('relay_all_recipients', 0) == 1,
                'relay_unknown_only': domain_data.get('relay_unknown_only', 0) == 1,
                'dns_checks': dns_checks or {},
                'alias_domains': alias_entries
            })
        
        active_count = sum(1 for d in result_domains if d.get('active'))
        
        return {
            'domains': result_domains,
            'total': len(result_domains),
            'active': active_count,
            'last_dns_check': format_datetime_for_api(last_check.checked_at) if (last_check and last_check.checked_at) else None
        }


@router.get("/domains/all")
async def get_all_domains_with_dns():
    """Get all domains with cached DNS checks"""
    try:
        domains = await mailcow_api.get_domains()
        
        return await asyncio.to_thread(_build_domain_list_worker, domains)

    except Exception as e:
        logger.error(f"Error fetching domains: {e}")
        raise internal_error(e)


@router.get("/domains/{domain}/dns-check")
async def check_single_domain_dns(domain: str):
    """
    Check DNS records for a specific domain
    
    Args:
        domain: Domain name to check
        
    Returns:
        DNS check results for the domain
    """
    try:
        dns_data = await check_domain_dns(domain)
        return dns_data
    except Exception as e:
        logger.error(f"Error checking DNS for {domain}: {e}")
        raise internal_error(e)


def _record_value(check: Optional[Dict[str, Any]]) -> Optional[str]:
    """The published DNS value from a check result, or None."""
    if not isinstance(check, dict):
        return None
    value = check.get('record')
    return value.strip() if isinstance(value, str) and value.strip() else None


def _definitely_absent(check: Optional[Dict[str, Any]]) -> bool:
    """True when the lookup succeeded and the record genuinely does not exist.

    A DNS timeout or resolver failure must NOT count as "removed", otherwise a
    transient network problem would fire a false alarm.
    """
    if not isinstance(check, dict):
        return False
    if _record_value(check) is not None:
        return False
    message = (check.get('message') or '').lower()
    return 'not found' in message or 'no dane' in message or 'not published' in message


def detect_dns_changes(previous: Optional[DomainDNSCheck],
                       dns_data: Dict[str, Any]) -> List[Dict[str, str]]:
    """Compare a fresh check against the stored one and list real changes.

    Only reports a change when we are sure: both values present and different,
    or a value that existed is now definitively gone. Failed lookups are
    ignored so DNS hiccups never trigger an alert.
    """
    if not previous:
        return []   # first check for this domain - nothing to compare against

    changes = []
    for key, label, column in (
        ('spf', 'SPF', 'spf_check'),
        ('dkim', 'DKIM', 'dkim_check'),
        ('dmarc', 'DMARC', 'dmarc_check'),
        ('tlsa', 'TLSA (DANE)', 'tlsa_check'),
        ('mta_sts', 'MTA-STS', 'mta_sts_check'),
        ('tls_rpt', 'TLS-RPT', 'tls_rpt_check'),
    ):
        old_check = getattr(previous, column, None)
        new_check = dns_data.get(key)
        old_value = _record_value(old_check)
        new_value = _record_value(new_check)

        if old_value and new_value and old_value != new_value:
            changes.append({'type': label, 'old': old_value, 'new': new_value})
        elif old_value and new_value is None and _definitely_absent(new_check):
            changes.append({'type': label, 'old': old_value, 'new': '(removed)'})
        elif old_value is None and new_value and _definitely_absent(old_check):
            changes.append({'type': label, 'old': '(none)', 'new': new_value})

    # States that break or weaken delivery without any record value changing
    old_dnssec = getattr(previous, 'dnssec_check', None)
    new_dnssec = dns_data.get('dnssec')
    if (isinstance(old_dnssec, dict) and isinstance(new_dnssec, dict)
            and old_dnssec.get('status') == 'success'
            and new_dnssec.get('status') in ('warning', 'error')):
        changes.append({'type': 'DNSSEC', 'old': old_dnssec.get('message') or 'validated',
                        'new': new_dnssec.get('message') or 'not validated'})

    old_tlsa = getattr(previous, 'tlsa_check', None)
    new_tlsa = dns_data.get('tlsa')
    if isinstance(new_tlsa, dict):
        old_mismatch = set(old_tlsa.get('certificate_mismatch') or []) if isinstance(old_tlsa, dict) else set()
        new_mismatch = [h for h in new_tlsa.get('certificate_mismatch') or [] if h not in old_mismatch]
        if new_mismatch:
            changes.append({'type': 'DANE', 'old': 'TLSA record matched the certificate',
                            'new': f'TLSA record does not match the certificate of {", ".join(new_mismatch)}'})
    return changes


def notify_dns_changes(domain_name: str, changes: List[Dict[str, str]]) -> None:
    """Send a DNS-change alert (email + notification destinations)."""
    if not changes:
        return
    try:
        from ..services.notification_service import notify

        types = ', '.join(c['type'] for c in changes)
        subject = f"DNS records changed for {domain_name}: {types}"
        lines = [
            f"The following DNS records changed for {domain_name}:",
            "",
        ]
        for change in changes:
            lines.append(f"{change['type']}")
            lines.append(f"  before: {change['old']}")
            lines.append(f"  now:    {change['new']}")
            lines.append("")
        lines.append(
            "If you did not expect this, check the domain at your DNS provider. "
            "If mailcow generated new values (for example a new DKIM key), update "
            "the records at your registrar so mail keeps authenticating."
        )
        notify(subject, "\n".join(lines), alert_type="dns_changes")
        logger.info(f"DNS change alert sent for {domain_name}: {types}")
    except Exception as e:
        logger.error(f"Could not send DNS change alert for {domain_name}: {e}")


def store_dns_check_worker(domain_name, dns_data, is_full_check):
    """Own the session in the worker, including the async notification step."""
    with get_db_context() as db:
        asyncio.run(save_dns_check_to_db(db, domain_name, dns_data, is_full_check=is_full_check))


def _load_alias_map_for_dns_checks():
    with get_db_context() as db:
        return get_alias_domain_map(db)


async def save_dns_check_to_db(db: Session, domain_name: str, dns_data: Dict[str, Any], is_full_check: bool = False):
    """Save DNS check results to database (upsert), alerting on real changes."""
    try:
        checked_at = datetime.now(timezone.utc)

        existing = db.query(DomainDNSCheck).filter(
            DomainDNSCheck.domain_name == domain_name
        ).first()

        # Compare against the stored values BEFORE overwriting them
        changes = []
        if settings.dns_change_alerts_enabled:
            try:
                changes = detect_dns_changes(existing, dns_data)
            except Exception as e:
                logger.error(f"Could not compare DNS records for {domain_name}: {e}")

        if existing:
            existing.spf_check = dns_data.get('spf')
            existing.dkim_check = dns_data.get('dkim')
            existing.dmarc_check = dns_data.get('dmarc')
            existing.dnssec_check = dns_data.get('dnssec')
            existing.tlsa_check = dns_data.get('tlsa')
            existing.mta_sts_check = dns_data.get('mta_sts')
            existing.tls_rpt_check = dns_data.get('tls_rpt')
            existing.checked_at = checked_at
            existing.updated_at = checked_at
            existing.is_full_check = is_full_check
        else:
            new_check = DomainDNSCheck(
                domain_name=domain_name,
                spf_check=dns_data.get('spf'),
                dkim_check=dns_data.get('dkim'),
                dmarc_check=dns_data.get('dmarc'),
                dnssec_check=dns_data.get('dnssec'),
                tlsa_check=dns_data.get('tlsa'),
                mta_sts_check=dns_data.get('mta_sts'),
                tls_rpt_check=dns_data.get('tls_rpt'),
                checked_at=checked_at,
                is_full_check=is_full_check
            )
            db.add(new_check)

        db.commit()
        logger.info(f"Saved DNS check for {domain_name}")

        if changes:
            logger.warning(f"[DNS CHANGE] {domain_name}: {', '.join(c['type'] for c in changes)}")
            await asyncio.to_thread(notify_dns_changes, domain_name, changes)
        
    except Exception as e:
        logger.error(f"Error saving DNS check for {domain_name}: {e}")
        db.rollback()
        raise


def _public_cached_dns_result(result):
    """Hide legacy exception suffixes without changing saved DNS diagnostics."""
    if not isinstance(result, dict):
        return result
    message = result.get('message')
    prefixes = (
        'Failed to check SPF:', 'Failed to check DKIM:',
        'Failed to check DMARC:', 'Failed to check TLSA:',
        'Could not check MTA-STS record:',
        'MTA-STS record exists but the policy file could not be fetched:',
        'MTA-STS check failed:',
    )
    if isinstance(message, str):
        for prefix in prefixes:
            if message.startswith(prefix):
                return {**result, 'message': prefix[:-1] + '. Check the application logs.'}
    return result


def get_cached_dns_check(db: Session, domain_name: str) -> Dict[str, Any]:
    """Get cached DNS check from database"""
    try:
        cached = db.query(DomainDNSCheck).filter(
            DomainDNSCheck.domain_name == domain_name
        ).first()
        
        if cached:
            return {
                'spf': _public_cached_dns_result(cached.spf_check),
                'dkim': _public_cached_dns_result(cached.dkim_check),
                'dmarc': _public_cached_dns_result(cached.dmarc_check),
                'dnssec': _public_cached_dns_result(cached.dnssec_check),
                'tlsa': _public_cached_dns_result(cached.tlsa_check),
                'mta_sts': _public_cached_dns_result(cached.mta_sts_check),
                'tls_rpt': _public_cached_dns_result(cached.tls_rpt_check),
                'checked_at': format_datetime_for_api(cached.checked_at) if cached.checked_at else None
            }
        return None
        
    except Exception as e:
        logger.error(f"Error getting cached DNS for {domain_name}: {e}")
        return None


@router.post("/domains/check-all-dns")
async def check_all_domains_dns_manual():
    """Manually trigger DNS check for all active domains"""
    try:
        domains = await mailcow_api.get_domains()
        
        if not domains:
            return {
                'status': 'success',
                'message': 'No domains to check',
                'domains_checked': 0,
                'errors': []
            }
        
        active_domains = [d for d in domains if d.get('active', 0) == 1]

        checked_count = 0
        errors = []

        # Sources do not depend on the domain: resolve once per batch
        spf_source_ips = await get_spf_source_ips()

        names = [d.get('domain_name') for d in active_domains if d.get('domain_name')]
        # Alias domains are real sending domains: check them too (issue #92)
        alias_map = await asyncio.to_thread(_load_alias_map_for_dns_checks)
        names.extend(a for a in sorted(alias_map.keys()) if a not in names)

        for domain_name in names:

            try:
                dns_data = await check_domain_dns(domain_name, spf_source_ips)
                await asyncio.to_thread(store_dns_check_worker, domain_name, dns_data, True)
                checked_count += 1
            except Exception as e:
                logger.error("DNS check failed for %s: %s", domain_name, e)
                errors.append(f"{domain_name}: DNS check failed. Check the application logs.")
        
        status = 'success' if checked_count == len(names) else 'partial'
        
        return {
            'status': status,
            'message': f'Checked {checked_count} domains',
            'domains_checked': checked_count,
            'errors': errors
        }
        
    except Exception as e:
        logger.error(f"Error in manual DNS check: {e}")
        raise internal_error(e)


@router.post("/domains/{domain}/check-dns")
async def check_single_domain_dns_manual(domain: str):
    """Manually trigger DNS check for a single domain"""
    try:
        dns_data = await check_domain_dns(domain)
        await asyncio.to_thread(store_dns_check_worker, domain, dns_data, False)
        
        return {
            'status': 'success',
            'message': f'DNS checked for {domain}',
            'data': dns_data
        }
        
    except Exception as e:
        logger.error(f"Error checking DNS for {domain}: {e}")
        raise internal_error(e)
