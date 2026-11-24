import errno
import ipaddress
import logging
import socket

logger = logging.getLogger(__name__)

BLOCKED_MESSAGE = "demo mode: outbound network access is disabled"

_installed = False
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
    return _normalize(host) == "localhost"


def _lookup_allowed(host) -> bool:
    return _host_allowed(host) or _ip(host) is not None


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
    if not _host_allowed(ip):
        _blocked(ip)
        raise socket.herror(errno.ENETUNREACH, BLOCKED_MESSAGE)
    return _original["gethostbyaddr"](ip)


def install() -> None:
    global _installed
    if _installed:
        return

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
    # At INFO the app's default log level hides this notice.
    logger.warning("[DEMO] Outbound network disabled (allowed: loopback, localhost)")


def uninstall() -> None:
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
    _original.clear()
    _installed = False
