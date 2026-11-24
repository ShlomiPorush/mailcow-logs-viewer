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

ACTIVITY_TYPES = ('volume_spike', 'auth_failure_burst', 'smtp_abuse_block')

TITLE_MAX = 255
SUBJECT_MAX = 255

BREACH_DETAIL = 'An unusual sign-in may mean someone else has access.'


def types_in(areas: Iterable[str]) -> List[str]:
    wanted = set(areas)
    return sorted(t for t, area in ALERT_AREAS.items() if area in wanted)


def bounded_title(title: str) -> str:
    return title if len(title) <= TITLE_MAX else title[:TITLE_MAX - 3] + '...'


def record(alert_type: str, severity: str, title: str, detail: str,
           subject: Optional[str] = None, metric_value: Optional[float] = None) -> bool:
    try:
        with get_db_context() as db:
            db.add(SecurityAlert(
                alert_type=alert_type,
                severity=severity,
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
