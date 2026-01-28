"""
API endpoints for system reports and summary
"""
import logging
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from datetime import datetime, timezone
from typing import Dict, Any, List

from ..database import get_db
from ..config import settings
from ..services.smtp_service import send_notification_email

# Import existing API functions
from .mailbox_stats import get_mailbox_stats_summary, get_all_mailbox_stats
from .blacklist import get_monitored_hosts
from .status import get_mailcow_info, get_storage_status
from .domains import get_all_domains_with_dns

logger = logging.getLogger(__name__)

router = APIRouter()

async def get_system_summary_data(db: Session) -> Dict[str, Any]:
    """
    Aggregate system summary data using existing API endpoints logic
    """
    # 1. Traffic Stats (7 Days)
    traffic_data = await get_mailbox_stats_summary(date_range="7days", db=db)
    
    # 2. System Status (Domains, Mailboxes, Aliases)
    # Using get_mailcow_info to get Active/Total counts
    system_data = await get_mailcow_info()
    
    # 3. Storage Status
    storage_data = await get_storage_status()
    
    # 4. Blacklist Status
    blacklist_data = await get_monitored_hosts()
    
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
    top_failures_response = await get_all_mailbox_stats(
        date_range="7days",
        sort_by="failure_rate",
        sort_order="desc",
        page=1,
        page_size=20, # Fetch more to filter locally for actual failures > 0
        active_only=True,
        hide_zero=True,
        db=db
    )
    # Filter to only show mailboxes with combined_failed > 0
    raw_top_failures = top_failures_response.get('mailboxes', [])
    top_failures = [m for m in raw_top_failures if m.get('combined_failed', 0) > 0][:5]
    
    # 6. DNS Issues
    # /api/domains/all
    domains_response = await get_all_domains_with_dns(db=db)
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
        import asyncio
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
async def get_summary_report(db: Session = Depends(get_db)):
    """
    Get the weekly summary report data
    """
    return await get_system_summary_data(db)

@router.post("/system/summary/email")
async def send_summary_report_email(
    background_tasks: BackgroundTasks, 
    db: Session = Depends(get_db), 
    force: bool = False
):
    """
    Trigger sending the weekly summary email
    """
    if not settings.enable_weekly_summary and not force:
        return {"status": "skipped", "reason": "Weekly summary disabled"}
        
    # Run in background to not block the request
    background_tasks.add_task(generate_and_send_email, db)
    return {"status": "queued", "message": "Weekly summary email generation started"}

async def generate_and_send_email(db: Session = None):
    """
    Generate and send the weekly summary email
    """
    should_close = False
    
    # If no DB session provided (e.g. from scheduler), create a new one
    if db is None:
        from ..database import SessionLocal
        db = SessionLocal()
        should_close = True
        
    try:
        # Get all data
        data = await get_system_summary_data(db)
        
        system = data['system']
        traffic = data['traffic']
        storage = data['storage']
        blacklist = data['blacklist']
        top_failures = data['top_failures']
        dns_issues = data['dns_issues']
        queue = data['queue']
        quarantine = data['quarantine']

        # Format free storage
        storage_display = f"{storage['used_percent']}" 

        # --- PREPARE HTML TABLES ---
        
        # 1. Blacklist Rows
        hosts_list = blacklist.get('hosts', [])
        blacklist_rows = ""
        if hosts_list:
            for h in hosts_list:
                status = h.get('status', 'unknown')
                status_color = '#dc2626' if status == 'listed' else '#16a34a'
                
                details = '-'
                if status == 'listed':
                    results = h.get('results', [])
                    # FIX: Use 'name' instead of 'rbl'
                    listed_rbls = [str(r.get('name', 'Unknown')) for r in results if r.get('listed')]
                    details = ', '.join(listed_rbls)
                
                blacklist_rows += f"""
                                            <tr>
                                                <td>{h.get('hostname')}</td>
                                                <td>
                                                    <span style="color: {status_color}; font-weight: bold;">
                                                        {status.upper()}
                                                    </span>
                                                </td>
                                                <td style="font-size: 11px; color: #6b7280;">
                                                    {details}
                                                </td>
                                            </tr>
                """
        else:
             blacklist_rows = '<tr><td colspan="3" align="center">No hosts monitored</td></tr>'

        # 2. DNS Issues Rows
        dns_rows = ""
        if dns_issues:
             for item in dns_issues:
                 dns_rows += f"<tr><td>{item['domain']}</td><td style='color: #b45309;'>{', '.join(item['issues'])}</td></tr>"

        # 3. Top Failures Rows
        failures_rows = ""
        if top_failures:
            for m in top_failures:
                # FIX: Use 'combined_fails' if available, or fallbacks. Using correct key from mailbox_stats.
                failed_count = m.get('combined_failed', 0)
                fail_rate = m.get('combined_failure_rate', 0)
                failures_rows += f"""
                                            <tr>
                                                <td>{m.get('username')}</td>
                                                <td align="center">{m.get('combined_received', 0)}</td>
                                                <td align="center">{m.get('combined_sent', 0)}</td>
                                                <td align="center" style="color: #dc2626; font-weight: bold;">{failed_count}</td>
                                                <td align="center" style="color: #dc2626; font-weight: bold;">{fail_rate}%</td>
                                            </tr>
                """

        # Current Date
        # FIX: Date format to DD/MM/YYYY
        current_date = datetime.now().strftime('%d/%m/%Y')

        # New HTML Template Matching Requirements
        html_content = f"""
        <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
        <html xmlns="http://www.w3.org/1999/xhtml">
        <head>
            <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
            <title>Weekly Server Summary</title>
            <style type="text/css">
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333333; margin: 0; padding: 0; }}
                table {{ border-collapse: collapse; mso-table-lspace:0pt; mso-table-rspace:0pt; }}
                td, th {{ vertical-align: top; }}
                .stat-box {{ background-color: #f9fafb; border: 1px solid #e5e7eb; border-radius: 4px; padding: 15px; text-align: center; }}
                .stat-value {{ font-size: 20px; font-weight: bold; color: #1f2937; margin-bottom: 5px; }}
                .stat-label {{ font-size: 11px; color: #6b7280; text-transform: uppercase; font-weight: 600; }}
                .section-header {{ margin: 0 0 15px 0; font-size: 16px; color: #333333; border-bottom: 2px solid #f3f4f6; padding-bottom: 10px; }}
                .data-table {{ width: 100%; font-size: 13px; }}
                .data-table th {{ background-color: #f3f4f6; color: #6b7280; font-weight: 600; text-transform: uppercase; padding: 8px; text-align: left; font-size: 11px; }}
                .data-table td {{ padding: 8px; border-bottom: 1px solid #e5e7eb; color: #333333; }}
            </style>
        </head>
        <body style="margin: 0; padding: 0; background-color: #f4f4f4;">
            <table border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color: #f4f4f4; padding: 20px;">
                <tr>
                    <td align="center">
                        <table border="0" cellpadding="0" cellspacing="0" width="600" style="background-color: #ffffff; border-radius: 5px; overflow: hidden; box-shadow: 0 2px 5px rgba(0,0,0,0.1);">
                            
                            <!-- Header -->
                            <tr>
                                <td bgcolor="#2563eb" style="padding: 20px; text-align: center; color: #ffffff;">
                                    <h1 style="margin: 0; font-size: 24px;">Weekly Server Summary</h1>
                                    <p style="margin: 5px 0 0 0; font-size: 14px; opacity: 0.9;">{current_date}</p>
                                </td>
                            </tr>
                            
                            <!-- ZONE 1: System Summary -->
                            <tr>
                                <td style="padding: 25px 25px 10px 25px;">
                                    <h2 class="section-header">System Summary</h2>
                                    <table border="0" cellpadding="0" cellspacing="0" width="100%">
                                        <tr>
                                            <td width="32%" class="stat-box">
                                                <div class="stat-value">{system['mailboxes']['active']}</div>
                                                <div class="stat-label">Mailboxes</div>
                                            </td>
                                            <td width="2%">&nbsp;</td>
                                            <td width="32%" class="stat-box">
                                                <div class="stat-value">{system['aliases']['active']}</div>
                                                <div class="stat-label">Aliases</div>
                                            </td>
                                            <td width="2%">&nbsp;</td>
                                            <td width="32%" class="stat-box">
                                                <div class="stat-value">{system['domains']['active']}</div>
                                                <div class="stat-label">Domains</div>
                                            </td>
                                        </tr>
                                        <tr><td colspan="5" height="10"></td></tr>
                                        <tr>
                                            <td width="32%" class="stat-box">
                                                <div class="stat-value">{storage_display}</div>
                                                <div class="stat-label">Storage Used</div>
                                            </td>
                                            <td width="2%">&nbsp;</td>
                                            <td width="32%" class="stat-box">
                                                <div class="stat-value">{queue['count']}</div>
                                                <div class="stat-label">Queue</div>
                                            </td>
                                            <td width="2%">&nbsp;</td>
                                            <td width="32%" class="stat-box">
                                                <div class="stat-value">{quarantine['count']}</div>
                                                <div class="stat-label">Quarantine</div>
                                            </td>
                                        </tr>
                                    </table>
                                </td>
                            </tr>

                            <!-- ZONE 2: Email Traffic Summary -->
                            <tr>
                                <td style="padding: 10px 25px;">
                                    <h2 class="section-header">Email Traffic Summary</h2>
                                    <table border="0" cellpadding="0" cellspacing="0" width="100%">
                                        <tr>
                                            <td width="23%" class="stat-box">
                                                <div class="stat-value">{traffic['total_sent']}</div>
                                                <div class="stat-label">Sent</div>
                                            </td>
                                            <td width="2%">&nbsp;</td>
                                            <td width="23%" class="stat-box">
                                                <div class="stat-value">{traffic['total_received']}</div>
                                                <div class="stat-label">Received</div>
                                            </td>
                                            <td width="2%">&nbsp;</td>
                                            <td width="23%" class="stat-box">
                                                <div class="stat-value" style="color: #dc2626;">{traffic['sent_failed']}</div>
                                                <div class="stat-label">Failed</div>
                                            </td>
                                            <td width="2%">&nbsp;</td>
                                            <td width="23%" class="stat-box" style="background-color: {'#fee2e2' if traffic['failure_rate'] > 5 else '#dcfce7'}; border-color: {'#fecaca' if traffic['failure_rate'] > 5 else '#bbf7d0'};">
                                                <div class="stat-value" style="color: {'#dc2626' if traffic['failure_rate'] > 5 else '#16a34a'};">{traffic['failure_rate']}%</div>
                                                <div class="stat-label" style="color: {'#991b1b' if traffic['failure_rate'] > 5 else '#166534'};">Rating</div>
                                            </td>
                                        </tr>
                                    </table>
                                </td>
                            </tr>

                            <!-- ZONE 3: Blacklist Status -->
                            <tr>
                                <td style="padding: 10px 25px;">
                                    <h2 class="section-header">Blacklist Status</h2>
                                    <table border="0" cellpadding="0" cellspacing="0" class="data-table">
                                        <thead>
                                            <tr>
                                                <th>Address</th>
                                                <th>Status</th>
                                                <th>Details</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {blacklist_rows}
                                        </tbody>
                                    </table>
                                </td>
                            </tr>

                            <!-- ZONE 4: DNS Issues (Active & Errors Only) -->
                             {f'''
                            <tr>
                                <td style="padding: 10px 25px;">
                                    <h2 class="section-header" style="color: #d97706; border-color: #fef3c7;">DNS Issues (Active Domains)</h2>
                                    <table border="0" cellpadding="0" cellspacing="0" class="data-table">
                                        <thead>
                                            <tr style="background-color: #fffbeb;">
                                                <th style="color: #92400e;">Domain</th>
                                                <th style="color: #92400e;">Issue</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {dns_rows}
                                        </tbody>
                                    </table>
                                </td>
                            </tr>
                            ''' if dns_issues else ''}

                            <!-- ZONE 5: Top 5 Worst Mailboxes -->
                            {f'''
                            <tr>
                                <td style="padding: 10px 25px 25px 25px;">
                                    <h2 class="section-header" style="color: #dc2626; border-color: #fee2e2;">Top 5 Worst Rated Mailboxes</h2>
                                    <table border="0" cellpadding="0" cellspacing="0" class="data-table">
                                        <thead>
                                            <tr style="background-color: #fef2f2;">
                                                <th style="color: #991b1b;">Mailbox</th>
                                                <th style="text-align: center; color: #991b1b;">Recv</th>
                                                <th style="text-align: center; color: #991b1b;">Sent</th>
                                                <th style="text-align: center; color: #991b1b;">Fail</th>
                                                <th style="text-align: center; color: #991b1b;">Rating</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {failures_rows}
                                        </tbody>
                                    </table>
                                </td>
                            </tr>
                            ''' if top_failures else ''}

                            <!-- Footer -->
                            <tr>
                                <td bgcolor="#f4f4f4" align="center" style="padding: 20px; color: #9ca3af; font-size: 11px;">
                                    Generated by mailcow Logs Viewer
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
            </table>
        </body>
        </html>
        """
        
        recipient = settings.admin_email
        if recipient:
            # FIX: Subject date format
            subject = f"Weekly Server Summary - {current_date}"
            send_notification_email(
                recipient=recipient,
                subject=subject,
                text_content="Please view this email in an HTML-compatible client.",
                html_content=html_content
            )
            logger.info(f"Weekly summary report sent to {recipient}")
        else:
             logger.warning("Weekly summary enabled but no ADMIN_EMAIL configured.")

    except Exception as e:
        logger.error(f"Failed to generate/send weekly summary: {e}", exc_info=True)
    finally:
        if should_close:
            db.close()
