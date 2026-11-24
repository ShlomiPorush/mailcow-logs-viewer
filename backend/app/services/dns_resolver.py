import logging
import dns.asyncresolver
import dns.asyncquery
import dns.resolver
import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rcode
import dns.name
import dns.flags

logger = logging.getLogger(__name__)

UDP_DNS_SERVERS = [
    ['8.8.8.8', '8.8.4.4'],
    ['1.1.1.1', '1.0.0.1'],
]

DOH_URLS = [
    'https://cloudflare-dns.com/dns-query',
    'https://dns.google/dns-query',
]

# [] is the container's resolver and must stay first: Spamhaus refuses public resolvers
BLACKLIST_UDP_DNS_SERVERS = [
    [],
    ['9.9.9.9', '149.112.112.112'],
    ['1.1.1.1', '1.0.0.1'],
    ['8.8.8.8', '8.8.4.4'],
]

BLACKLIST_DOH_URLS = [
    'https://dns.quad9.net/dns-query',
]

BLOCKED_RESPONSE_PREFIX = '127.255.'


async def resolve(query: str, rdtype: str = 'A', timeout: int = 5):
    return await _resolve_with_fallback(query, rdtype, timeout, UDP_DNS_SERVERS, DOH_URLS)


async def resolve_for_blacklist(query: str, rdtype: str = 'A', timeout: int = 10):
    resolvers = _blacklist_resolver_list()
    last_error = None
    blocked_answer = None

    for dns_servers in resolvers:
        try:
            resolver = dns.asyncresolver.Resolver()
            if dns_servers:
                resolver.nameservers = list(dns_servers)
            resolver.timeout = timeout
            resolver.lifetime = timeout

            answer = await resolver.resolve(query, rdtype)

            if _is_blocked_answer(answer):
                blocked_answer = answer
                logger.debug("RBL rejected query via %s for %s - trying next resolver",
                             dns_servers or 'system', query)
                continue

            return answer

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            raise
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as e:
            last_error = str(e)
            continue
        except Exception as e:
            last_error = str(e)
            continue

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

    if blocked_answer is not None:
        return blocked_answer

    raise Exception(f"All blacklist resolvers failed for {query}: {last_error}")


def _blacklist_resolver_list():
    try:
        from ..config import settings
        configured = (getattr(settings, 'blacklist_dns_servers', '') or '').strip()
    except Exception:
        configured = ''

    if configured:
        custom = [s.strip() for s in configured.split(',') if s.strip()]
        if custom:
            return [custom] + BLACKLIST_UDP_DNS_SERVERS
    return BLACKLIST_UDP_DNS_SERVERS


def _is_blocked_answer(answer) -> bool:
    try:
        values = [str(r) for r in answer]
    except Exception:
        return False
    return bool(values) and all(v.startswith(BLOCKED_RESPONSE_PREFIX) for v in values)


async def _resolve_with_fallback(query: str, rdtype: str, timeout: int, udp_servers: list, doh_urls: list):
    last_error = None
    
    for dns_servers in udp_servers:
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.nameservers = dns_servers
            resolver.timeout = timeout
            resolver.lifetime = timeout
            
            return await resolver.resolve(query, rdtype)
            
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            raise
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as e:
            last_error = str(e)
            logger.debug(f"DNS UDP failed ({dns_servers[0]}) for {query}: {e}")
            continue
        except Exception as e:
            last_error = str(e)
            logger.debug(f"DNS UDP error ({dns_servers[0]}) for {query}: {e}")
            continue
    
    logger.info(f"All UDP DNS servers failed for {query}, trying DoH fallback...")
    
    for doh_url in doh_urls:
        try:
            q = dns.message.make_query(dns.name.from_text(query), rdtype)
            
            response = await dns.asyncquery.https(q, doh_url, timeout=timeout)
            
            if response.rcode() == dns.rcode.NXDOMAIN:
                raise dns.resolver.NXDOMAIN()

            if response.rcode() != dns.rcode.NOERROR:
                last_error = f"{doh_url} answered {dns.rcode.to_text(response.rcode())}"
                logger.debug(f"DoH failed ({doh_url}) for {query}: {last_error}")
                continue

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
    
    error_msg = f"All DNS resolvers failed for {query} (UDP + DoH)"
    if last_error:
        error_msg += f" - last error: {last_error}"
    logger.warning(error_msg)
    raise Exception(error_msg)


class DnssecAnswer:

    def __init__(self, rcode: int, authenticated: bool, records: list):
        self.rcode = rcode
        self.authenticated = authenticated
        self.records = records


def _dnssec_answer(response, rdtype: str) -> DnssecAnswer:
    wanted = dns.rdatatype.from_text(rdtype)
    records = [rdata for rrset in response.answer if rrset.rdtype == wanted for rdata in rrset]
    return DnssecAnswer(
        rcode=response.rcode(),
        authenticated=bool(response.flags & dns.flags.AD),
        records=records,
    )


async def resolve_dnssec(query: str, rdtype: str = 'A', timeout: int = 5,
                         checking_disabled: bool = False) -> DnssecAnswer:
    q = dns.message.make_query(dns.name.from_text(query), rdtype, want_dnssec=True)
    q.flags |= dns.flags.AD
    if checking_disabled:
        q.flags |= dns.flags.CD

    last_error = None
    servfail = None

    for dns_servers in UDP_DNS_SERVERS:
        for server in dns_servers:
            try:
                response, _ = await dns.asyncquery.udp_with_fallback(q, server, timeout=timeout)
            except Exception as e:
                last_error = str(e)
                logger.debug(f"DNSSEC query failed ({server}) for {query}: {e}")
                continue
            if response.rcode() == dns.rcode.SERVFAIL:
                servfail = response
                continue
            return _dnssec_answer(response, rdtype)

    if servfail is None:
        for doh_url in DOH_URLS:
            try:
                response = await dns.asyncquery.https(q, doh_url, timeout=timeout)
            except Exception as e:
                last_error = str(e)
                logger.debug(f"DNSSEC DoH failed ({doh_url}) for {query}: {e}")
                continue
            if response.rcode() == dns.rcode.SERVFAIL:
                servfail = response
                continue
            return _dnssec_answer(response, rdtype)

    if servfail is not None:
        return _dnssec_answer(servfail, rdtype)

    raise Exception(f"All DNS resolvers failed for {query} (DNSSEC) - last error: {last_error}")
