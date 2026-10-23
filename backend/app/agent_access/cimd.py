"""Client ID Metadata Documents: a client whose client_id is an https URL.

The document at that URL names the client and lists its redirect addresses
(draft-ietf-oauth-client-id-metadata-document-00). Fetching a URL a stranger
chose is a server-side request, so it is fenced in: only after a person signed
in, https on port 443 only, every resolved address must be public, the
connection goes to the vetted address (no second DNS lookup) with the
certificate checked against the host name, no redirects, no proxy from the
environment, no compression, at most 64 KB and 5 seconds. Failures are not
cached; good documents are cached in memory.
"""
import asyncio
import ipaddress
import json
import logging
import socket
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

import httpx

logger = logging.getLogger(__name__)

MAX_URL_LENGTH = 512
MAX_BYTES = 64 * 1024
TIMEOUT_SECONDS = 5.0
CACHE_MAX_ENTRIES = 100
CACHE_DEFAULT_SECONDS = 3600
CACHE_MIN_SECONDS = 300
CACHE_MAX_SECONDS = 86400
MAX_CONCURRENT_FETCHES = 4


class ClientDocumentError(Exception):
    """The client's metadata document cannot be used; the message is shown to the person."""


@dataclass(frozen=True)
class ClientDocument:
    client_id: str
    client_name: str
    redirect_uris: Tuple[str, ...]
    publisher: str


_cache: Dict[str, Tuple[float, ClientDocument]] = {}
_semaphore: Optional[asyncio.Semaphore] = None


def is_document_client_id(client_id: str) -> bool:
    return bool(client_id) and client_id.startswith("https://")


def _check_url(url: str) -> Tuple[str, str]:
    """(host, path with query) of an acceptable document URL."""
    if len(url) > MAX_URL_LENGTH:
        raise ClientDocumentError("The client's address is too long.")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise ClientDocumentError("The client's address is not valid.")
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.fragment:
        raise ClientDocumentError("The client's address must be a plain https address.")
    if port not in (None, 443):
        raise ClientDocumentError("The client's address must use the standard https port.")
    if not parts.path or parts.path == "/":
        raise ClientDocumentError("The client's address must name a document.")
    host = parts.hostname.lower()
    try:
        ipaddress.ip_address(host)
        raise ClientDocumentError("The client's address must use a host name.")
    except ValueError:
        pass
    target = parts.path + (f"?{parts.query}" if parts.query else "")
    return host, target


_NAT64 = ipaddress.ip_network("64:ff9b::/96")


def _public_one(ip) -> bool:
    return (ip.is_global and not ip.is_multicast and not ip.is_private and not ip.is_loopback
            and not ip.is_link_local and not ip.is_reserved and not ip.is_unspecified
            and not getattr(ip, "is_site_local", False))


def _public(address: str) -> bool:
    """Whether an address is a public unicast one, IPv4 carried inside IPv6 included."""
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    if not _public_one(ip) and not (isinstance(ip, ipaddress.IPv6Address) and ip in _NAT64):
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = [ip.ipv4_mapped, ip.sixtofour, ip.teredo[1] if ip.teredo else None,
                    ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF) if ip in _NAT64 else None]
        if any(v4 is not None and not _public_one(v4) for v4 in embedded):
            return False
    return True


async def _resolve(host: str) -> str:
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(loop.getaddrinfo(host, 443, type=socket.SOCK_STREAM), TIMEOUT_SECONDS)
    except (OSError, asyncio.TimeoutError):
        raise ClientDocumentError("The client's host could not be found.")
    addresses = [info[4][0] for info in infos]
    if not addresses:
        raise ClientDocumentError("The client's host could not be found.")
    if not all(_public(a) for a in addresses):
        raise ClientDocumentError("The client's host is not a public address.")
    return addresses[0]


def _cache_seconds(cache_control: str) -> int:
    seconds = CACHE_DEFAULT_SECONDS
    for part in (cache_control or "").split(","):
        name, _, value = part.strip().partition("=")
        if name.lower() in ("no-store", "no-cache"):
            return CACHE_MIN_SECONDS
        if name.lower() == "max-age" and value.isdigit():
            seconds = int(value)
    return max(CACHE_MIN_SECONDS, min(CACHE_MAX_SECONDS, seconds))


def parse_document(url: str, body: bytes, publisher: str) -> ClientDocument:
    """Validate the document's content (also used by tests)."""
    from .oauth import valid_redirect_uri  # local import: oauth imports this module

    try:
        doc = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ClientDocumentError("The client's document is not valid JSON.")
    if not isinstance(doc, dict):
        raise ClientDocumentError("The client's document is not a JSON object.")
    if doc.get("client_id") != url:
        raise ClientDocumentError("The client's document names another client.")
    name = doc.get("client_name")
    if not isinstance(name, str) or not name.strip() or len(name) > 100:
        raise ClientDocumentError("The client's document has no usable name.")
    uris = doc.get("redirect_uris")
    if not isinstance(uris, list) or not uris or len(uris) > 20 \
            or not all(isinstance(u, str) and valid_redirect_uri(u) for u in uris):
        raise ClientDocumentError("The client's document has no usable redirect addresses.")
    method = doc.get("token_endpoint_auth_method", "none")
    if method != "none":
        raise ClientDocumentError("The client wants a sign-in method this app does not offer.")
    return ClientDocument(url, name.strip(), tuple(uris), publisher)


async def fetch(url: str) -> ClientDocument:
    """The client's document, from the cache or the web, within TIMEOUT_SECONDS in all.

    The deadline covers waiting for a free fetch, the DNS lookup and the whole
    download: httpx's own timeout only limits each read, so a server sending a
    byte every few seconds would otherwise hold a fetch for as long as it likes.
    """
    cached = _cache.get(url)
    if cached and cached[0] > time.monotonic():
        return cached[1]
    host, target = _check_url(url)
    try:
        async with asyncio.timeout(TIMEOUT_SECONDS):
            return await _fetch(url, host, target)
    except TimeoutError:
        logger.info(f"Agent access: the client document of {host} took too long")
        raise ClientDocumentError("The client's document took too long to fetch.")


async def _fetch(url: str, host: str, target: str) -> ClientDocument:
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(MAX_CONCURRENT_FETCHES)
    async with _semaphore:
        address = await _resolve(host)
        netloc = f"[{address}]" if ":" in address else address
        pinned = urlunsplit(("https", netloc, target, "", ""))
        try:
            async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS, follow_redirects=False, trust_env=False) as client:
                async with client.stream(
                    "GET", pinned,
                    headers={"Host": host, "Accept": "application/json", "Accept-Encoding": "identity"},
                    extensions={"sni_hostname": host},
                ) as response:
                    if response.status_code != 200:
                        raise ClientDocumentError(f"The client's document answered {response.status_code}.")
                    encoding = response.headers.get("content-encoding", "identity").strip().lower()
                    if encoding not in ("", "identity"):
                        raise ClientDocumentError("The client's document came compressed.")
                    length = response.headers.get("content-length")
                    if length and length.isdigit() and int(length) > MAX_BYTES:
                        raise ClientDocumentError("The client's document is too large.")
                    body = bytearray()
                    async for chunk in response.aiter_raw():
                        body.extend(chunk)
                        if len(body) > MAX_BYTES:
                            raise ClientDocumentError("The client's document is too large.")
                    cache_control = response.headers.get("cache-control", "")
        except ClientDocumentError:
            raise
        except (httpx.HTTPError, OSError) as e:
            logger.info(f"Agent access: could not fetch the client document of {host}: {type(e).__name__}")
            raise ClientDocumentError("The client's document could not be fetched.")
    document = parse_document(url, bytes(body), host)
    if len(_cache) >= CACHE_MAX_ENTRIES:
        _cache.pop(min(_cache, key=lambda k: _cache[k][0]), None)
    _cache[url] = (time.monotonic() + _cache_seconds(cache_control), document)
    return document
