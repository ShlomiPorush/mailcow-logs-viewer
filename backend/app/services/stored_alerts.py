"""
The alerts Needs attention and the bell list (the security_alerts table).

Anomaly detection and SMTP abuse protection write their own alerts. This module
writes the ones that otherwise go only by email or a notification channel: DNS
changes, DMARC & TLS report import errors, and the protection rules' possible
stolen password and addresses they could not ban.

Each alert type belongs to one area of the app, which decides who may view and
dismiss it (routers/security_alerts.py). A type missing here belongs to no
area: only an admin sees it.

Writing an alert is best effort: in its own session, and a failure is logged and
never stops the notification or the job that found it. The alert keeps a short
summary; the email, the channels and the page the alert opens keep the details.
"""
import logging
from datetime import datetime
from typing import Dict, Iterable, List, Optional

from ..database import get_db_context
from ..models import SecurityAlert

logger = logging.getLogger(__name__)

ALERT_AREAS: Dict[str, str] = {
    'volume_spike': 'security',
    'auth_failure_burst': 'security',
    'smtp_abuse_block': 'security',
    'protection_breach': 'security',
    'protection_ban_failed': 'security',
    'dns_change': 'domains',
    'dmarc_import_failed': 'dmarc',
}

# The alerts whose activity (GET /api/security-alerts/{id}/activity) can be shown
ACTIVITY_TYPES = ('volume_spike', 'auth_failure_burst', 'smtp_abuse_block')

# The columns' sizes (models.SecurityAlert)
TITLE_MAX = 255
SUBJECT_MAX = 255

BREACH_DETAIL = 'An unusual sign-in may mean someone else has access.'


def types_in(areas: Iterable[str]) -> List[str]:
    """The alert types of these areas."""
    wanted = set(areas)
    return sorted(t for t, area in ALERT_AREAS.items() if area in wanted)


def bounded_title(title: str) -> str:
    """The title cut to its column; a long domain or user name can pass it."""
    return title if len(title) <= TITLE_MAX else title[:TITLE_MAX - 3] + '...'


def record(alert_type: str, severity: str, title: str, detail: str,
           subject: Optional[str] = None, metric_value: Optional[float] = None) -> bool:
    """Store one alert in its own session. False, logged, when it could not be stored."""
    try:
        with get_db_context() as db:
            db.add(SecurityAlert(
                alert_type=alert_type,
                severity=severity,
                # A subject longer than its column is left out rather than cut: it names the alert's
                # domain or account, and a cut one would name another
                subject=subject if subject and len(subject) <= SUBJECT_MAX else None,
                title=bounded_title(title),
                detail=detail,
                metric_value=metric_value,
                created_at=datetime.utcnow(),
            ))
        return True
    except Exception as e:
        logger.error(f"Could not store the {alert_type} alert for Needs attention: {e}")
        return False


def dns_types_line(changes: List[Dict[str, str]]) -> str:
    """The alert's line: SPF changed. / SPF and DKIM changed. / SPF, DKIM and 2 more
    changed. Each kind of change once, in the order found; no record values."""
    labels = list(dict.fromkeys(str(c.get('type')) for c in changes if c.get('type')))
    if len(labels) == 1:
        named = labels[0]
    elif len(labels) == 2:
        named = f'{labels[0]} and {labels[1]}'
    else:
        named = f'{labels[0]}, {labels[1]} and {len(labels) - 2} more'
    return f'{named} changed.'


def record_dns_change(domain_name: str, changes: List[Dict[str, str]]) -> bool:
    if not any(c.get('type') for c in changes or []):
        return False
    return record('dns_change', 'warning', f'DNS changes detected for {domain_name}', dns_types_line(changes),
                  subject=domain_name, metric_value=len(changes))


def record_dmarc_import_failed(failed_emails: List[Dict]) -> bool:
    n = len(failed_emails or [])
    if not n:
        return False
    return record('dmarc_import_failed', 'warning', 'DMARC & TLS report import errors',
                  f"Could not fully import {n} report {'email' if n == 1 else 'emails'}.", metric_value=n)


def breach_subject(target: str, usernames: Optional[Iterable[str]]) -> str:
    """The account a possible stolen password is about: the first of its user names, else the address."""
    names = sorted(str(u).strip() for u in (usernames or []) if u and str(u).strip())
    return names[0] if names else target


def record_protection_breach(target: str, usernames: Optional[Iterable[str]]) -> bool:
    subject = breach_subject(target, usernames)
    return record('protection_breach', 'critical', f'Possible stolen password: {subject}', BREACH_DETAIL,
                  subject=subject)


def record_protection_ban_failed(targets: Iterable[str]) -> bool:
    n = len(set(targets))
    if not n:
        return False
    return record('protection_ban_failed', 'warning', 'Protection rules could not ban addresses',
                  f"Could not ban {n} {'address or network' if n == 1 else 'addresses or networks'}.",
                  metric_value=n)
