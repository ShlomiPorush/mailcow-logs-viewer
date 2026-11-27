import ipaddress
import re
from typing import Optional, Tuple

_RULE_MATCH = re.compile(r'^(\S+) matched rule id \d+')
_OWN_LINES = re.compile(
    r'^(?:Banning|Unbanning|(?:Add|Added|Remove|Removed) host/network) (\S+)'
    r'|^\d+ more attempts in the next \d+ seconds until (\S+) is banned'
    r'|^Address (\S+) is (?:allowlisted|whitelisted) by rule '
    r'|^(\S+) is not banned, (?:skipping unban|removing it from the unban queue)'
)
_MAILCOWAUTH_FAILURE = re.compile(
    r'^\S+ matched rule id \d+ \(MAILCOWAUTH: Login failed for user (.*) '
    r'with service ([a-z0-9]*) from IP [0-9a-f.:]+\)\Z', re.S)


def netfilter_address(message: Optional[str]) -> Optional[str]:
    message = message or ''
    match = _RULE_MATCH.match(message) or _OWN_LINES.match(message)
    if not match:
        return None
    token = next(group for group in match.groups() if group).split('/', 1)[0]
    try:
        address = ipaddress.ip_address(token)
    except ValueError:
        return None
    if address.version == 6 and address.ipv4_mapped:
        address = address.ipv4_mapped
    return str(address)


def mailcowauth_failure(message: Optional[str]) -> Optional[Tuple[str, str]]:
    match = _MAILCOWAUTH_FAILURE.match(message or '')
    return (match.group(1), match.group(2)) if match else None
