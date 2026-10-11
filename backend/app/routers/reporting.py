"""
API endpoints for system reports and summary
"""
import asyncio
import logging
from fastapi import APIRouter, HTTPException, BackgroundTasks
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Tuple

from ..database import get_db_context
from ..config import settings
from ..services.smtp_service import send_notification_email

# Import existing API functions
from .mailbox_stats import get_mailbox_stats_summary, get_all_mailbox_stats
from .blacklist import get_monitored_hosts
from .status import get_mailcow_info, get_storage_status
from .domains import get_all_domains_with_dns

logger = logging.getLogger(__name__)

router = APIRouter()

def _get_summary_statistics_worker():
    """Materialize both database snapshots within a worker-owned session."""
    with get_db_context() as db:
        traffic = get_mailbox_stats_summary(date_range="7days", db=db)
        failures = get_all_mailbox_stats(
            date_range="7days",
            sort_by="failure_rate",
            sort_order="desc",
            page=1,
            page_size=20,
            active_only=True,
            hide_zero=True,
            db=db,
        )
        return traffic, failures


async def get_system_summary_data() -> Dict[str, Any]:
    """
    Aggregate system summary data using existing API endpoints logic
    """
    # 1. Traffic Stats (7 Days)
    traffic_data, top_failures_response = await asyncio.to_thread(_get_summary_statistics_worker)
    
    # 2. System Status (Domains, Mailboxes, Aliases)
    # Using get_mailcow_info to get Active/Total counts
    system_data = await get_mailcow_info()
    
    # 3. Storage Status
    storage_data = await get_storage_status()
    
    # 4. Blacklist Status
    # get_monitored_hosts() is a sync function (FastAPI runs it in the
    # threadpool); awaiting it directly raised TypeError and broke every
    # weekly summary (#81). Run it off the event loop the same way.
    blacklist_data = await asyncio.to_thread(get_monitored_hosts)
    
    # Aggregate blacklist status
    hosts = blacklist_data.get('hosts', [])
    listed_hosts = [h for h in hosts if h.get('status') == 'listed']
    blacklist_summary = {
        "status": "listed" if listed_hosts else "clean",
        "listed_count": len(listed_hosts),
        "total_hosts": len(hosts),
        "hosts": hosts
    }

    # 5. Top 5 Mailboxes with Failures
    # /api/mailbox-stats/all?date_range=7days&sort_by=failure_rate&sort_order=desc&page=1&page_size=5&active_only=true&hide_zero=true
    # Filter to only show mailboxes with combined_failed > 0
    raw_top_failures = top_failures_response.get('mailboxes', [])
    top_failures = [m for m in raw_top_failures if m.get('combined_failed', 0) > 0][:5]
    
    # 6. DNS Issues
    # /api/domains/all
    domains_response = await get_all_domains_with_dns()
    all_domains = domains_response.get('domains', [])
    
    issues_list = []
    for d in all_domains:
        # Filter active domains only
        if not d.get('active'):
            continue
            
        domain_name = d.get('domain_name')
        checks = d.get('dns_checks', {}) or {}
        domain_issues = []
        
        # SPF
        spf = checks.get('spf', {}) or {}
        if spf.get('status') == 'error' or (spf.get('valid') is False and spf.get('status') != 'warning'):
             msg = spf.get('message') or spf.get('error') or 'Invalid'
             domain_issues.append(f"SPF: {msg}")

        # DKIM
        dkim = checks.get('dkim', {}) or {}
        if dkim.get('status') == 'error' or (dkim.get('match') is False and dkim.get('status') != 'warning'):
             msg = dkim.get('message') or 'Invalid'
             domain_issues.append(f"DKIM: {msg}")
             
        # DMARC
        dmarc = checks.get('dmarc', {}) or {}
        if dmarc.get('status') == 'error':
             msg = dmarc.get('message') or 'Invalid'
             domain_issues.append(f"DMARC: {msg}")
        
        if domain_issues:
            issues_list.append({
                "domain": domain_name,
                "issues": domain_issues
            })

    # 7. Queue and Quarantine
    try:
        from ..mailcow_api import mailcow_api
        queue_data, quarantine_data = await asyncio.gather(
            mailcow_api.get_queue(),
            mailcow_api.get_quarantine()
        )
        queue_count = len(queue_data) if isinstance(queue_data, list) else 0
        quarantine_count = len(quarantine_data) if isinstance(quarantine_data, list) else 0
    except Exception as e:
        logger.error(f"Failed to fetch queue/quarantine data: {e}")
        queue_count = 0
        quarantine_count = 0

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "traffic": traffic_data,
        "system": system_data,
        "storage": storage_data,
        "blacklist": blacklist_summary,
        "top_failures": top_failures,
        "dns_issues": issues_list,
        "queue": {"count": queue_count},
        "quarantine": {"count": quarantine_count}
    }

@router.get("/system/summary")
async def get_summary_report():
    """
    Get the weekly summary report data
    """
    return await get_system_summary_data()

@router.post("/system/summary/email")
def send_summary_report_email(
    background_tasks: BackgroundTasks, 
    force: bool = False
):
    """
    Trigger sending the weekly summary email
    """
    if not settings.enable_weekly_summary and not force:
        return {"status": "skipped", "reason": "Weekly summary disabled"}
        
    # Run in background to not block the request
    background_tasks.add_task(generate_and_send_email)
    return {"status": "queued", "message": "Weekly summary email generation started"}

def _n(value) -> str:
    """A count with thousands separators; anything else as it is."""
    return f"{value:,}" if isinstance(value, int) and not isinstance(value, bool) else str(value)


def _listed_on(host) -> List[str]:
    return [str(r.get('name', 'Unknown')) for r in host.get('results', []) if r.get('listed')]


def build_summary_email(data: Dict[str, Any], now: datetime = None) -> Tuple[str, str, str]:
    """Subject, plain text and HTML of the weekly summary."""
    from ..services import email_layout as e

    now = now or datetime.now()
    system = data['system']
    traffic = data['traffic']
    storage = data['storage']
    hosts = data['blacklist'].get('hosts', [])
    top_failures = data['top_failures']
    dns_issues = data['dns_issues']
    queue = data['queue']['count']
    quarantine = data['quarantine']['count']

    start = now - timedelta(days=6)
    period = f"{start.day} {start.strftime('%b')} to {now.day} {now.strftime('%b %Y')}"
    listed = [h for h in hosts if h.get('status') == 'listed']
    rate = traffic.get('failure_rate', 0) or 0
    rate_high = rate > 5

    attention = []
    if listed:
        attention.append(f"{len(listed)} host{'s' if len(listed) != 1 else ''} on a blacklist")
    if dns_issues:
        attention.append(f"DNS issues on {len(dns_issues)} domain{'s' if len(dns_issues) != 1 else ''}")
    if rate_high:
        attention.append(f"a failure rate of {rate}%")
    if attention:
        intro = f"{period}. Needs a look: {', '.join(attention)}."
    else:
        intro = f"{period}. Nothing needs your attention."

    blocks = [
        e.stats([
            ('Sent', _n(traffic.get('total_sent', 0))),
            ('Received', _n(traffic.get('total_received', 0))),
            ('Failed', _n(traffic.get('sent_failed', 0)), 'fail' if traffic.get('sent_failed') else None),
            ('Failure rate', f"{rate}%", 'fail' if rate_high else 'ok', 'Above 5%' if rate_high else 'Under 5%'),
            ('Queue', _n(queue), 'warn' if queue else None),
            ('Quarantine', _n(quarantine), 'warn' if quarantine else None),
        ]),
        e.panel('System', e.kv([
            ('Mailboxes', _n(system['mailboxes']['active'])),
            ('Aliases', _n(system['aliases']['active'])),
            ('Domains', _n(system['domains']['active'])),
            ('Storage used', storage['used_percent']),
        ])),
        e.panel('Blacklists', e.table(['Host', 'Status', 'Listed on'], [
            [h.get('hostname'),
             e.tag('Listed', 'fail') if h.get('status') == 'listed' else e.tag(str(h.get('status', 'unknown')).capitalize(), 'ok' if h.get('status') == 'clean' else 'muted'),
             ', '.join(_listed_on(h)) if h.get('status') == 'listed' else '-']
            for h in hosts
        ], empty='No hosts are monitored'), count=len(hosts) or None),
    ]
    if dns_issues:
        blocks.append(e.panel('DNS issues', e.table(
            ['Domain', 'Issue'], [[i['domain'], '\n'.join(i['issues'])] for i in dns_issues]), count=len(dns_issues)))
    if top_failures:
        blocks.append(e.panel('Mailboxes with the most failures', e.table(
            ['Mailbox', ('Received', 'right'), ('Sent', 'right'), ('Failed', 'right'), ('Rate', 'right')],
            [[m.get('username'), _n(m.get('combined_received', 0)), _n(m.get('combined_sent', 0)),
              e.strong(_n(m.get('combined_failed', 0)), 'fail'), e.strong(f"{m.get('combined_failure_rate', 0)}%", 'fail')]
             for m in top_failures])))

    html_content = e.render(
        title='Your server this week', topic='Weekly summary', tone='info', intro=intro, blocks=blocks,
        footer='The weekly summary is on in Settings, Notifications.', when=now)

    lines = ['Your server this week', intro, '',
             f"Sent: {_n(traffic.get('total_sent', 0))}",
             f"Received: {_n(traffic.get('total_received', 0))}",
             f"Failed: {_n(traffic.get('sent_failed', 0))}",
             f"Failure rate: {rate}%",
             f"Queue: {_n(queue)}",
             f"Quarantine: {_n(quarantine)}", '',
             f"Mailboxes: {_n(system['mailboxes']['active'])}",
             f"Aliases: {_n(system['aliases']['active'])}",
             f"Domains: {_n(system['domains']['active'])}",
             f"Storage used: {storage['used_percent']}", '', 'Blacklists:']
    lines += [f"  {h.get('hostname')}: {h.get('status', 'unknown')}"
              + (f" ({', '.join(_listed_on(h))})" if h.get('status') == 'listed' else '') for h in hosts] or ['  No hosts are monitored']
    if dns_issues:
        lines += ['', 'DNS issues:'] + [f"  {i['domain']}: {'; '.join(i['issues'])}" for i in dns_issues]
    if top_failures:
        lines += ['', 'Mailboxes with the most failures:'] + [
            f"  {m.get('username')}: {_n(m.get('combined_failed', 0))} failed ({m.get('combined_failure_rate', 0)}%)"
            for m in top_failures]
    lines += ['', 'The weekly summary is on in Settings, Notifications.']

    subject = f"Weekly summary: {period}"
    return subject, '\n'.join(lines), html_content


async def generate_and_send_email():
    """
    Generate and send the weekly summary email
    """
    try:
        data = await get_system_summary_data()
        subject, text_content, html_content = build_summary_email(data)

        recipient = settings.admin_email
        if recipient:
            # Send in executor - smtplib blocks the event loop
            await asyncio.get_running_loop().run_in_executor(
                None,
                send_notification_email,
                recipient,
                subject,
                text_content,
                html_content
            )
            logger.info(f"Weekly summary report sent to {recipient}")
        else:
             logger.warning("Weekly summary enabled but no ADMIN_EMAIL configured.")

    except Exception as e:
        logger.error(f"Failed to generate/send weekly summary: {e}", exc_info=True)
