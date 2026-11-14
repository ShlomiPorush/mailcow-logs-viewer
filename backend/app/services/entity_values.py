"""One reading of an IP address, an email address and a domain.

The entity card, the watchlist and the search all look a value up by the form
returned here, so the same value always finds the same rows:

- IP: one address (no network, no interface scope), written as Python's
  ipaddress writes it (IPv6 compressed and lower case). An IPv4 address
  mapped into IPv6 (::ffff:192.0.2.1) is the IPv4 address, as the Netfilter
  logs store it.
- Email address: split on the LAST '@' (a quoted local part may hold one),
  compared in lower case. The domain part is read as a domain.
- Domain: IDNA to ASCII, lower case, without a trailing dot.

Surrounding whitespace is dropped; whitespace or a control character inside
the value is refused, as is a value longer than an address (254) or a domain
(253) can be. detect_kind() is the rule the search box mirrors in the
browser (utils.js).

fail2ban_entry_problem() is the stricter check for a value written to the
Fail2ban allowlist or denylist: there nothing is trimmed, because mailcow
keeps those lists as one comma or newline separated text.
"""
import ipaddress
import re
import unicodedata
from typing import List, Optional, Tuple

import idna  # IDNA 2008 with UTS #46 mapping; httpx depends on it

ADDRESS_MAX = 254
LOCAL_MAX = 64
DOMAIN_MAX = 253
IP_MAX = 64

KINDS = ("ip", "address", "domain")

_LABEL = re.compile(r'^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$')
_PREFIX = re.compile(r'^\d{1,3}$')


class InvalidValue(ValueError):
    """A value that is not one IP address, email address or domain; the text says why."""


def _unsafe_char(value: str) -> bool:
    """Whitespace, or a control, format or separator character (a zero width space is one)."""
    for ch in value:
        if ch.isspace() or unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp", "Zs"):
            return True
    return False


def _clean(value, max_length: int, what: str, slack: int = 0) -> str:
    """The value without surrounding whitespace; slack allows characters the
    caller drops itself (a domain's trailing dot)."""
    if not isinstance(value, str):
        raise InvalidValue(f"Enter {what}.")
    value = value.strip()
    if not value:
        raise InvalidValue(f"Enter {what}.")
    if len(value) > max_length + slack:
        raise InvalidValue(f"That is too long for {what} ({max_length} characters at most).")
    if _unsafe_char(value):
        raise InvalidValue(f"Enter {what}, without spaces or control characters.")
    return value


# ---------------------------------------------------------------- IP

def normalize_ip(value) -> str:
    """One IP address in its canonical form, or InvalidValue."""
    value = _clean(value, IP_MAX, "one IP address")
    if "/" in value:
        raise InvalidValue("Enter one IP address, not a network.")
    if "%" in value:
        raise InvalidValue("Enter the IP address without an interface (the part after %).")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise InvalidValue("Enter one IP address, like 192.0.2.1 or 2001:db8::1.")
    if address.version == 6 and address.ipv4_mapped:
        address = address.ipv4_mapped
    return str(address)


_MAPPED_PREFIXES = ("::ffff:", "0:0:0:0:0:ffff:", "0000:0000:0000:0000:0000:ffff:")


def ip_spellings(ip: str) -> List[str]:
    """A closed set of texts that hold the canonical address ip, for an
    indexed IN (...) on a stored column: the canonical form, and for IPv4 the
    IPv4-mapped IPv6 spellings (three prefixes, the tail dotted, in compressed
    hex or in zero-padded hex, lower and upper case); for IPv6 the compressed
    and exploded forms in both cases, and for an IPv4-compatible address
    (::a.b.c.d) the same three tails after its prefixes. Any other spelling
    needs same_ip()."""
    address = ipaddress.ip_address(ip)
    if address.version == 6:
        forms = [str(address), address.exploded]
        if address != ipaddress.IPv6Address(0) and int(address) >> 32 == 0:
            # IPv4-compatible (::a.b.c.d): glibc's inet_ntop, which Rspamd uses, writes
            # the tail dotted. Another address than a.b.c.d or ::ffff:a.b.c.d
            forms += _embedded_ipv4_forms(ipaddress.IPv4Address(int(address)), _COMPATIBLE_PREFIXES)
        return list(dict.fromkeys(forms + [f.upper() for f in forms]))
    forms = _embedded_ipv4_forms(address, _MAPPED_PREFIXES)
    return list(dict.fromkeys([str(address)] + forms + [f.upper() for f in forms]))


_COMPATIBLE_PREFIXES = ("::", "0:0:0:0:0:0:", "0000:0000:0000:0000:0000:0000:")


def _embedded_ipv4_forms(address: ipaddress.IPv4Address, prefixes) -> List[str]:
    """An IPv4 address as the tail of an IPv6 text after each prefix: dotted,
    in compressed hex and in zero-padded hex (lower case)."""
    packed = address.packed
    high, low = (packed[0] << 8) | packed[1], (packed[2] << 8) | packed[3]
    tails = (str(address), f"{high:x}:{low:x}", f"{high:04x}:{low:04x}")
    return [prefix + tail for prefix in prefixes for tail in tails]


def spellings_of_typed_ip(value) -> List[str]:
    """ip_spellings of a typed address; text that is not one address as it was
    typed (compared with a stored address, it then matches nothing)."""
    try:
        return ip_spellings(normalize_ip(value))
    except InvalidValue:
        return [value.strip() if isinstance(value, str) else value]


def same_ip(stored, ip: str) -> bool:
    """Whether stored text holds the address ip (canonical) by value: any
    spelling of an IPv6 address, an IPv4 address mapped into IPv6. Text that
    is not one address (a network, a host name, garbage) holds none."""
    if not isinstance(stored, str):
        return False
    try:
        address = ipaddress.ip_address(stored.strip())
    except ValueError:
        return False
    if address.version == 6 and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address == ipaddress.ip_address(ip)


def fail2ban_entry_problem(value) -> Optional[str]:
    """Why a value cannot be one Fail2ban list entry, or None when it is one IP
    address or one network (address/prefix). Nothing is trimmed: a comma, a line
    break or any whitespace would make it several entries in mailcow's list."""
    problem = "'ip' must be one IP address or one network, like 192.0.2.1 or 192.0.2.0/24"
    if not isinstance(value, str) or not value or len(value) > IP_MAX:
        return problem
    if _unsafe_char(value) or "," in value or "%" in value:
        return problem
    host, slash, prefix = value.partition("/")
    try:
        if slash:
            # Only address/prefix; ipaddress would also take a netmask
            if not _PREFIX.match(prefix):
                return problem
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(host)
    except ValueError:
        return problem
    return None


# ---------------------------------------------------------------- domain

def _to_ascii(value: str) -> str:
    if value.isascii():
        return value.lower()
    try:
        return idna.encode(value, uts46=True).decode("ascii").lower()
    except idna.IDNAError:
        raise InvalidValue("Enter a valid domain, like example.com.")


def normalize_domain(value) -> str:
    """One domain as ASCII (IDNA) in lower case without a trailing dot, or InvalidValue."""
    value = _clean(value, DOMAIN_MAX, "one domain", slack=1)
    if value.endswith("."):
        value = value[:-1]
    if "@" in value or "/" in value or ":" in value:
        raise InvalidValue("Enter a domain, like example.com.")
    ascii_name = _to_ascii(value)
    if len(ascii_name) > DOMAIN_MAX:
        raise InvalidValue(f"That is too long for a domain ({DOMAIN_MAX} characters at most).")
    labels = ascii_name.split(".")
    if len(labels) < 2 or not all(_LABEL.match(label) for label in labels):
        raise InvalidValue("Enter a valid domain, like example.com.")
    # 192.0.2.1 is an address, not a domain
    if labels[-1].isdigit():
        raise InvalidValue("Enter a valid domain, like example.com.")
    return ascii_name


def domain_forms(domain: str) -> List[str]:
    """A normalized domain as ASCII and, when it is an IDN, in Unicode too: logs
    keep the form the mail had."""
    forms = [domain]
    if "xn--" in domain:
        try:
            forms.append(idna.decode(domain).lower())
        except idna.IDNAError:
            pass
    return list(dict.fromkeys(forms))


# ---------------------------------------------------------------- address

def normalize_address(value) -> Tuple[str, str]:
    """(lookup form, display form) of one email address, or InvalidValue.

    The lookup form is the local part in lower case, '@', the domain as
    normalize_domain() writes it. The display form is the value as given,
    without surrounding whitespace."""
    display = _clean(value, ADDRESS_MAX, "one email address")
    local, at, domain = display.rpartition("@")
    if not at or not local:
        raise InvalidValue("Enter one email address, like ann@example.com.")
    if len(local) > LOCAL_MAX:
        raise InvalidValue(f"The part before @ is too long ({LOCAL_MAX} characters at most).")
    try:
        domain = normalize_domain(domain)
    except InvalidValue:
        raise InvalidValue("Enter one email address, like ann@example.com.")
    normalized = f"{local.lower()}@{domain}"
    if len(normalized) > ADDRESS_MAX:
        raise InvalidValue(f"That is too long for an email address ({ADDRESS_MAX} characters at most).")
    return normalized, display


def address_forms(address: str) -> List[str]:
    """A normalized address with each form of its domain (see domain_forms)."""
    local, _, domain = address.rpartition("@")
    return [f"{local}@{d}" for d in domain_forms(domain)]


def address_domain(address: str) -> str:
    return address.rpartition("@")[2]


# ---------------------------------------------------------------- kind

def normalize(kind: str, value) -> str:
    """The lookup form of a value of a kind ('ip', 'address' or 'domain')."""
    if kind == "ip":
        return normalize_ip(value)
    if kind == "address":
        return normalize_address(value)[0]
    if kind == "domain":
        return normalize_domain(value)
    raise ValueError(f"Unknown kind: {kind}")


def detect_kind(value) -> Optional[str]:
    """What a typed value is: 'address' when it has an '@', else 'ip', else
    'domain', or None when it is none of them."""
    if not isinstance(value, str):
        return None
    for kind in (("address",) if "@" in value else ("ip", "domain")):
        try:
            normalize(kind, value)
            return kind
        except InvalidValue:
            continue
    return None
