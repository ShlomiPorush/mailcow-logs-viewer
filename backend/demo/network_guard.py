"""
Process-wide outbound network guard for the demo image.

The demo must never reach a real server, whatever a code path tries: the
mailcow API, SMTP, IMAP, DNS, blocklists, MaxMind or a webhook. Instead of
trusting every service to honour a flag, the demo patches the socket module
once at startup so that the only reachable destinations are the loopback
interface, Unix sockets and the PostgreSQL host. Anything else fails the same
way an unreachable network does, so the application's normal error handling
takes over.

The guard only sees connections made through Python's socket module. That is
why the demo image runs uvicorn on the asyncio loop (uvloop connects in C).
PostgreSQL is reached through libpq, which is C as well and unaffected.
"""
import errno
import ipaddress
import logging
import socket

logger = logging.getLogger(__name__)

BLOCKED_MESSAGE = "demo mode: outbound network access is disabled"

_installed = False
_allowed_hosts: set[str] = set()
_allowed_ips: set[str] = set()
_original = {}


def _normalize(host) -> str:
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    return str(host).lower().rstrip(".")


def _ip(host):
    try:
        return ipaddress.ip_address(_normalize(host).split("%", 1)[0])
    except ValueError:
        return None


def _host_allowed(host) -> bool:
    if host is None:
        return True
    ip = _ip(host)
    if ip is not None and ip.is_loopback:
        return True
    name = _normalize(host)
    return name in _allowed_hosts or name in _allowed_ips


def _lookup_allowed(host) -> bool:
    # A literal IP needs no DNS lookup; connect() decides whether it is reachable.
    return _host_allowed(host) or _ip(host) is not None


# DNS and DNS over TLS stay blocked even on loopback: Docker's embedded
# resolver listens on 127.0.0.11 and forwards unknown names to the host's
# upstream servers. Name resolution for the database host goes through libc
# in C and is not affected.
_DNS_PORTS = frozenset({53, 853})


def _address_allowed(sock, address) -> bool:
    if getattr(socket, "AF_UNIX", None) is not None and sock.family == socket.AF_UNIX:
        return True
    if isinstance(address, tuple) and len(address) >= 2 and address[1] in _DNS_PORTS:
        return False
    host = address[0] if isinstance(address, tuple) and address else address
    return _host_allowed(host)


def _blocked(target):
    if isinstance(target, bytes):
        target = target.decode("ascii", "replace")
    logger.warning(f"[DEMO] Blocked outbound connection to {target}")
    return OSError(errno.ENETUNREACH, BLOCKED_MESSAGE)


def _guarded_connect(self, address):
    if not _address_allowed(self, address):
        raise _blocked(address)
    return _original["connect"](self, address)


def _guarded_connect_ex(self, address):
    if not _address_allowed(self, address):
        _blocked(address)
        return errno.ENETUNREACH
    return _original["connect_ex"](self, address)


def _guarded_sendto(self, data, *args):
    # sendto(data, address) or sendto(data, flags, address)
    address = args[-1] if args else None
    if address is not None and not _address_allowed(self, address):
        raise _blocked(address)
    return _original["sendto"](self, data, *args)


def _guarded_sendmsg(self, buffers, ancdata=(), flags=0, address=None):
    if address is not None and not _address_allowed(self, address):
        raise _blocked(address)
    if address is None:
        return _original["sendmsg"](self, buffers, ancdata, flags)
    return _original["sendmsg"](self, buffers, ancdata, flags, address)


def _guarded_getaddrinfo(host, *args, **kwargs):
    if not _lookup_allowed(host):
        _blocked(host)
        raise socket.gaierror(socket.EAI_NONAME, BLOCKED_MESSAGE)
    return _original["getaddrinfo"](host, *args, **kwargs)


def _guarded_gethostbyname(host):
    if not _lookup_allowed(host):
        _blocked(host)
        raise socket.gaierror(socket.EAI_NONAME, BLOCKED_MESSAGE)
    return _original["gethostbyname"](host)


def _guarded_gethostbyname_ex(host):
    if not _lookup_allowed(host):
        _blocked(host)
        raise socket.gaierror(socket.EAI_NONAME, BLOCKED_MESSAGE)
    return _original["gethostbyname_ex"](host)


def _guarded_gethostbyaddr(ip):
    # Reverse lookups go to a DNS server even for a literal address.
    if not _host_allowed(ip):
        _blocked(ip)
        raise socket.herror(errno.ENETUNREACH, BLOCKED_MESSAGE)
    return _original["gethostbyaddr"](ip)


def install(allowed_hosts=()) -> None:
    """Patch the socket module. Idempotent.

    ``allowed_hosts`` are names (normally the PostgreSQL host) that stay
    reachable; they are resolved once here so connect() can match their IPs.
    """
    global _installed
    if _installed:
        return

    for host in allowed_hosts:
        if not host:
            continue
        name = _normalize(host)
        _allowed_hosts.add(name)
        try:
            for info in socket.getaddrinfo(name, None):
                _allowed_ips.add(info[4][0])
        except OSError:
            # Not resolvable yet (database container still starting); the
            # name itself stays allowed and connect() by name re-resolves.
            pass
    _allowed_hosts.add("localhost")

    cls = socket.socket
    _original.update(
        connect=cls.connect,
        connect_ex=cls.connect_ex,
        sendto=cls.sendto,
        sendmsg=getattr(cls, "sendmsg", None),
        getaddrinfo=socket.getaddrinfo,
        gethostbyname=socket.gethostbyname,
        gethostbyname_ex=socket.gethostbyname_ex,
        gethostbyaddr=socket.gethostbyaddr,
    )
    cls.connect = _guarded_connect
    cls.connect_ex = _guarded_connect_ex
    cls.sendto = _guarded_sendto
    if _original["sendmsg"] is not None:
        cls.sendmsg = _guarded_sendmsg
    socket.getaddrinfo = _guarded_getaddrinfo
    socket.gethostbyname = _guarded_gethostbyname
    socket.gethostbyname_ex = _guarded_gethostbyname_ex
    socket.gethostbyaddr = _guarded_gethostbyaddr

    _installed = True
    # WARNING: the app's default log level hides INFO, and this must be visible
    logger.warning(f"[DEMO] Outbound network disabled (allowed: loopback, {', '.join(sorted(_allowed_hosts))})")


def uninstall() -> None:
    """Restore the socket module (tests only)."""
    global _installed
    if not _installed:
        return
    cls = socket.socket
    cls.connect = _original["connect"]
    cls.connect_ex = _original["connect_ex"]
    cls.sendto = _original["sendto"]
    if _original["sendmsg"] is not None:
        cls.sendmsg = _original["sendmsg"]
    socket.getaddrinfo = _original["getaddrinfo"]
    socket.gethostbyname = _original["gethostbyname"]
    socket.gethostbyname_ex = _original["gethostbyname_ex"]
    socket.gethostbyaddr = _original["gethostbyaddr"]
    _allowed_hosts.clear()
    _allowed_ips.clear()
    _original.clear()
    _installed = False
