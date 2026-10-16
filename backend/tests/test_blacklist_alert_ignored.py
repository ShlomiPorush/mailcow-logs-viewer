"""The blacklist alert counts only hosts listed on a blacklist that alerts.

A host listed only on a list the user hid, or on UCEPROTECT Level 2/3 (never
alerted on), does not trigger the alert - but it used to be counted in the
subject ("2 hosts are on a blacklist") and listed in the body.
"""
import asyncio

from app import scheduler
from app.services import blacklist_service, notification_service

LISTED = {'name': 'Spamhaus ZEN', 'zone': 'zen.spamhaus.org', 'listed': True}
UCEPROTECT = {'name': 'UCEPROTECT Level 2', 'zone': 'dnsbl-2.uceprotect.net', 'listed': True}
HIDDEN = {'name': 'Barracuda', 'zone': 'b.barracudacentral.org', 'listed': True, 'ignored': True}

RESULTS = {
    '203.0.113.25': [LISTED],
    '203.0.113.26': [UCEPROTECT],
    '203.0.113.27': [HIDDEN],
}


def test_alert_counts_only_hosts_on_lists_that_alert(monkeypatch):
    monkeypatch.setattr(scheduler, '_load_blacklist_hosts_worker',
                        lambda: [{'hostname': ip, 'source': 'config'} for ip in RESULTS])
    monkeypatch.setattr(blacklist_service, 'get_cached_blacklist_check',
                        lambda ip: {'listed_count': 1, 'total_blacklists': 50, 'results': RESULTS[ip]})
    for name in ('start_batch_scan', 'end_batch_scan', 'update_batch_status', 'mark_host_as_processed_batch'):
        monkeypatch.setattr(blacklist_service, name, lambda *a, **kw: None)
    monkeypatch.setattr(scheduler.settings._inner, 'admin_email', 'admin@example.com')
    monkeypatch.setattr(scheduler, '_blacklist_last_listed_actionable_count', 0)
    sent = []
    monkeypatch.setattr(notification_service, 'notify',
                        lambda subject, text, html, recipient, alert_type: sent.append((subject, text))
                        or {'email': True, 'channels_sent': 0})
    saved = dict(scheduler.job_status['blacklist_check'])
    try:
        asyncio.run(scheduler._run_check_monitored_hosts(False, True))
    finally:
        scheduler.job_status['blacklist_check'] = saved

    assert [subject for subject, _ in sent] == ['Blacklist: 1 host is on a blacklist']
    hosts = [line for line in sent[0][1].splitlines() if line.startswith('Host: ')]
    assert hosts == ['Host: 203.0.113.25 (config)']
