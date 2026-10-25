"""Undo netfilter lines attributed to an address from the client's text.

Earlier versions read the offender of a netfilter line that starts with an IPv6
address from the first IPv4 anywhere in the line, which holds text the client
chose (a sasl_username, a Dovecot user=<...>, a non-SMTP command). The
protection rules could catch, and ban, that address.

An open catch that waits to be banned or reviewed (watching, pending) is
closed as expired when one of its stored log lines names another address
than the caught one, so a rule catches the address again if it really
attacks. Lines that retention already deleted prove nothing and close
nothing. Bans already written to Fail2ban are left as they are; a
contradicted one is logged for review. Lines whose stored
address is not the one netfilter named lose the address and its GeoIP data;
the message itself is kept.

The address logic is a frozen copy of app/services/netfilter_address.py.

Revision ID: 0024
Revises: 0023
Create Date: 2026-10-25
"""
import ipaddress
import logging
import re
from datetime import datetime

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text


revision = "0024"
down_revision = "0023"
branch_labels = None
depends_on = None

logger = logging.getLogger("app.migrations")

BAN_RULES = ["trap", "unknown_accounts", "repeat_offender", "subnet", "country"]
BATCH = 5000
CLOSED_REASON = "Closed on upgrade: its log lines name another address as the source."

_RULE_MATCH = re.compile(r'^(\S+) matched rule id \d+')
_OWN_LINES = re.compile(
    r'^(?:Banning|Unbanning|(?:Add|Added|Remove|Removed) host/network) (\S+)'
    r'|^\d+ more attempts in the next \d+ seconds until (\S+) is banned'
    r'|^Address (\S+) is (?:allowlisted|whitelisted) by rule '
    r'|^(\S+) is not banned, skipping unban'
)


def netfilter_address(message):
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


def _names(target, ip):
    """The line's address is the caught address, or inside the caught network."""
    if "/" not in target:
        return ip == target
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(target, strict=False)
    except ValueError:
        return False


def _contradicted(bind, hit):
    """One of the catch's stored lines names another address than the caught one,
    or than the address stored with it. Lines that retention already deleted,
    and lines that name no address, prove nothing either way."""
    ids = sorted({i for i in (hit.log_ids or []) if isinstance(i, int)})
    if not ids:
        return False
    rows = bind.execute(text("SELECT ip, message FROM netfilter_logs WHERE id = ANY(:ids)"), {"ids": ids}).all()
    for row in rows:
        named = netfilter_address(row.message)
        if named is not None and (named != row.ip or not _names(hit.ip, named)):
            return True
    return False


def _repair_hits(bind):
    now = datetime.utcnow()
    hits = bind.execute(text(
        "SELECT id, ip, rule, status, log_ids FROM protection_hits "
        "WHERE status IN ('watching', 'pending', 'banned') AND rule = ANY(:rules) ORDER BY id"
    ), {"rules": BAN_RULES}).all()
    for hit in hits:
        if not _contradicted(bind, hit):
            continue
        if hit.status == "banned":
            logger.warning(f"[PROTECTION] Upgrade: {hit.ip} stays banned by the {hit.rule} rule, but its log lines "
                           f"name another address as the source. Review it on the Security page.")
            continue
        bind.execute(text(
            "UPDATE protection_hits SET status = 'expired', mode = 'watch', ended_at = :now, error = NULL, "
            "reason = :reason WHERE id = :id"
        ), {"now": now, "reason": CLOSED_REASON, "id": hit.id})
        logger.warning(f"[PROTECTION] Upgrade: closed the {hit.status} catch of {hit.ip} by the {hit.rule} rule, "
                       f"its log lines name another address as the source")


def _repair_lines(bind):
    last, cleared = 0, 0
    while True:
        # A rule match that starts with its own stored address is right; every other line is checked here
        rows = bind.execute(text(
            "SELECT id, ip, message FROM netfilter_logs WHERE id > :last AND ip IS NOT NULL "
            "AND NOT starts_with(COALESCE(message, ''), ip || ' matched rule id ') ORDER BY id LIMIT :batch"
        ), {"last": last, "batch": BATCH}).all()
        if not rows:
            break
        last = rows[-1].id
        wrong = [r.id for r in rows if netfilter_address(r.message) != r.ip]
        if wrong:
            bind.execute(text(
                "UPDATE netfilter_logs SET ip = NULL, country_code = NULL, country_name = NULL, city = NULL, "
                "asn = NULL, asn_org = NULL WHERE id = ANY(:ids)"
            ), {"ids": wrong})
            cleared += len(wrong)
    if cleared:
        logger.warning(f"[NETFILTER] Upgrade: cleared the address of {cleared} log line(s) "
                       f"that netfilter did not attribute to it")


def repair(bind):
    tables = set(sa.inspect(bind).get_table_names())
    if "netfilter_logs" not in tables:
        return
    if "protection_hits" in tables:
        _repair_hits(bind)
    _repair_lines(bind)


def upgrade() -> None:
    repair(op.get_bind())


def downgrade() -> None:
    # The cleared addresses are not restored
    pass
