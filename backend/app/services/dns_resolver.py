"""
Centralized DNS resolver with DNS-over-HTTPS (DoH) fallback.

Strategy: UDP first (fast), DoH fallback when UDP port 53 is blocked.
This allows the application to work on VPS providers that block outgoing UDP 53.
"""
import logging
import dns.asyncresolver
import dns.asyncquery
import dns.resolver
import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rcode
import dns.name

logger = logging.getLogger(__name__)

# Traditional UDP DNS servers (tried first - fast path)
UDP_DNS_SERVERS = [
    ['8.8.8.8', '8.8.4.4'],      # Google DNS
    ['1.1.1.1', '1.0.0.1'],      # Cloudflare DNS
]

# DoH endpoints (fallback when UDP 53 is blocked)
DOH_URLS = [
    'https://cloudflare-dns.com/dns-query',
    'https://dns.google/dns-query',
]

# Blacklist (RBL) resolvers.
#
# IMPORTANT: Spamhaus (and several other RBLs) refuse queries that arrive via
# public/open resolvers - Google, Cloudflare, Quad9 and every public DoH
# endpoint. Instead of a real answer they return a code in 127.255.255.0/24,
# which means "your query was rejected", NOT "this IP is clean".
#
# So RBL lookups must go through your OWN recursive resolver. The first entry
# below (empty list) means "use the resolver configured for this container"
# (/etc/resolv.conf) - in a mailcow deployment that is unbound-mailcow, which
# is exactly what Spamhaus expects. Public resolvers are kept only as a last
# resort for the other ~44 zones that do allow them.
#
# Set BLACKLIST_DNS_SERVERS to point at a specific recursive resolver
# (e.g. "172.22.1.254" for mailcow's unbound) if the container's default
# resolver is a public one.
BLACKLIST_UDP_DNS_SERVERS = [
    [],                                   # system resolver (/etc/resolv.conf) - preferred
    ['9.9.9.9', '149.112.112.112'],       # Quad9      (serves real Spamhaus data)
    ['1.1.1.1', '1.0.0.1'],               # Cloudflare (Spamhaus rejects: 127.255.255.254)
    ['8.8.8.8', '8.8.4.4'],               # Google     (Spamhaus returns false NXDOMAIN - keep last)
]

# DoH is a public endpoint by definition, so it can never satisfy Spamhaus.
# Kept only so non-Spamhaus zones still work when UDP/53 is blocked outbound.
BLACKLIST_DOH_URLS = [
    'https://dns.quad9.net/dns-query',
]

# Answers in this range are rejection codes, not listings
BLOCKED_RESPONSE_PREFIX = '127.255.'


async def resolve(query: str, rdtype: str = 'A', timeout: int = 5):
    """
    Resolve a DNS query with UDP-first, DoH-fallback strategy.
    
    Args:
        query: DNS query string (domain name)
        rdtype: DNS record type ('A', 'TXT', 'MX', etc.)
        timeout: Timeout in seconds per attempt
        
    Returns:
        DNS answer object
        
    Raises:
        dns.resolver.NXDOMAIN: Domain does not exist
        dns.resolver.NoAnswer: No records of this type
        Exception: All resolvers failed
    """
    return await _resolve_with_fallback(query, rdtype, timeout, UDP_DNS_SERVERS, DOH_URLS)


async def resolve_for_blacklist(query: str, rdtype: str = 'A', timeout: int = 10):
    """
    Resolve a DNS query for blacklist checks.
    Uses blacklist-specific DNS servers (Quad9, Spamhaus authoritative)
    with Quad9 DoH as final fallback (Spamhaus blocks Google/Cloudflare).
    
    Args:
        query: DNS query string (reversed IP + blacklist zone)
        rdtype: DNS record type (usually 'A')
        timeout: Timeout in seconds per attempt
        
    Returns:
        DNS answer object
        
    Raises:
        dns.resolver.NXDOMAIN: IP not listed (valid response)
        dns.resolver.NoAnswer: IP not listed (valid response)
        Exception: All resolvers failed
    """
    resolvers = _blacklist_resolver_list()
    last_error = None
    blocked_answer = None

    # Phase 1: UDP resolvers, in order of preference
    for dns_servers in resolvers:
        try:
            resolver = dns.asyncresolver.Resolver()
            if dns_servers:                       # empty list = system resolver
                resolver.nameservers = list(dns_servers)
            resolver.timeout = timeout
            resolver.lifetime = timeout

            answer = await resolver.resolve(query, rdtype)

            # A 127.255.255.x answer means the RBL REJECTED the query (open
            # resolver / rate limit), not that the IP is listed. Treat it as a
            # transport failure and try the next resolver.
            if _is_blocked_answer(answer):
                blocked_answer = answer
                logger.debug("RBL rejected query via %s for %s - trying next resolver",
                             dns_servers or 'system', query)
                continue

            return answer

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            # Valid "not listed" responses - re-raise immediately
            raise
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as e:
            last_error = str(e)
            continue
        except Exception as e:
            last_error = str(e)
            continue

    # Phase 2: DoH (public by definition - will not satisfy Spamhaus, but
    # keeps the other zones working when UDP/53 is blocked)
    for doh_url in BLACKLIST_DOH_URLS:
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.nameservers = [doh_url]
            answer = await resolver.resolve(query, rdtype, tcp=True)
            if _is_blocked_answer(answer):
                blocked_answer = answer
                continue
            return answer
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            raise
        except Exception as e:
            last_error = str(e)
            continue

    # Every resolver was rejected: surface the rejection so the caller reports
    # "unknown", never "clean"
    if blocked_answer is not None:
        return blocked_answer

    raise Exception(f"All blacklist resolvers failed for {query}: {last_error}")


def _blacklist_resolver_list():
    """Resolver list for RBL lookups, honouring BLACKLIST_DNS_SERVERS."""
    try:
        from ..config import settings
        configured = (getattr(settings, 'blacklist_dns_servers', '') or '').strip()
    except Exception:
        configured = ''

    if configured:
        custom = [s.strip() for s in configured.split(',') if s.strip()]
        if custom:
            # Explicit operator choice wins; keep the rest as fallback
            return [custom] + BLACKLIST_UDP_DNS_SERVERS
    return BLACKLIST_UDP_DNS_SERVERS


def _is_blocked_answer(answer) -> bool:
    """True if every A record is an RBL rejection code (127.255.255.x)."""
    try:
        values = [str(r) for r in answer]
    except Exception:
        return False
    return bool(values) and all(v.startswith(BLOCKED_RESPONSE_PREFIX) for v in values)


async def _resolve_with_fallback(query: str, rdtype: str, timeout: int, udp_servers: list, doh_urls: list):
    """
    Internal: Try UDP resolvers first, fall back to DoH if all UDP attempts fail.
    
    NXDOMAIN and NoAnswer are valid DNS responses and are re-raised immediately.
    Only transport-level failures (timeout, no nameservers) trigger fallback.
    """
    last_error = None
    
    # Phase 1: Try traditional UDP DNS servers
    for dns_servers in udp_servers:
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.nameservers = dns_servers
            resolver.timeout = timeout
            resolver.lifetime = timeout
            
            return await resolver.resolve(query, rdtype)
            
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            # Valid DNS responses - re-raise immediately, no fallback needed
            raise
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as e:
            last_error = str(e)
            logger.debug(f"DNS UDP failed ({dns_servers[0]}) for {query}: {e}")
            continue
        except Exception as e:
            last_error = str(e)
            logger.debug(f"DNS UDP error ({dns_servers[0]}) for {query}: {e}")
            continue
    
    # Phase 2: All UDP servers failed - try DoH (port 443)
    logger.info(f"All UDP DNS servers failed for {query}, trying DoH fallback...")
    
    for doh_url in doh_urls:
        try:
            q = dns.message.make_query(dns.name.from_text(query), rdtype)
            
            response = await dns.asyncquery.https(q, doh_url, timeout=timeout)
            
            # Check for NXDOMAIN in DoH response
            if response.rcode() == dns.rcode.NXDOMAIN:
                raise dns.resolver.NXDOMAIN()
            
            # Check for no answer
            answer_section = response.answer
            if not answer_section:
                raise dns.resolver.NoAnswer()
            
            logger.info(f"DoH fallback succeeded ({doh_url}) for {query}")
            return dns.resolver.Answer(
                qname=dns.name.from_text(query),
                rdtype=dns.rdatatype.from_text(rdtype),
                rdclass=dns.rdataclass.IN,
                response=response,
            )
            
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            raise
        except Exception as e:
            last_error = str(e)
            logger.debug(f"DoH failed ({doh_url}) for {query}: {e}")
            continue
    
    # All methods exhausted
    error_msg = f"All DNS resolvers failed for {query} (UDP + DoH)"
    if last_error:
        error_msg += f" - last error: {last_error}"
    logger.warning(error_msg)
    raise Exception(error_msg)
