"""The address mailcow netfilter attributed a log line to.

netfilter writes '<addr> matched rule id N (<original log line>)'. The original
line holds text the remote client chose (a non-SMTP command, a sasl_username, a
Dovecot user=<...>), so the address is read only from the fields netfilter
writes itself: the address that leads a rule match, or the one in its own ban,
unban, warning and list lines. An address anywhere else in the text is never
the offender.
"""
import ipaddress
import re
from typing import Optional, Tuple

_RULE_MATCH = re.compile(r'^(\S+) matched rule id \d+')
# Older mailcow versions write "Add/Remove host/network ... blacklist" and "whitelisted",
# newer ones "Added/Removed ... denylist" and "allowlisted"
_OWN_LINES = re.compile(
    r'^(?:Banning|Unbanning|(?:Add|Added|Remove|Removed) host/network) (\S+)'
    r'|^\d+ more attempts in the next \d+ seconds until (\S+) is banned'
    r'|^Address (\S+) is (?:allowlisted|whitelisted) by rule '
    r'|^(\S+) is not banned, (?:skipping unban|removing it from the unban queue)'
)
# Since mailcow 2026-11 every failed IMAP, POP3, Sieve and SMTP login reaches
# netfilter as one line that mailcow writes: "MAILCOWAUTH: Login failed for user
# <username> with service <service> from IP <address>". The username is the
# client's own text, so the service and address are read from the end of the
# line, which mailcow writes after it.
_MAILCOWAUTH_FAILURE = re.compile(
    r'^\S+ matched rule id \d+ \(MAILCOWAUTH: Login failed for user (.*) '
    r'with service ([a-z0-9]*) from IP [0-9a-f.:]+\)\Z', re.S)


def netfilter_address(message: Optional[str]) -> Optional[str]:
    """The offender of a netfilter line, IPv4 or IPv6, or None when netfilter named none."""
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
    """(username, service) of a failed login netfilter matched in mailcow's own
    line, or None for any other line. The username can be empty."""
    match = _MAILCOWAUTH_FAILURE.match(message or '')
    return (match.group(1), match.group(2)) if match else None
