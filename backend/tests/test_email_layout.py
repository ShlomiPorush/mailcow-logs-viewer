"""Every email the app sends uses the shared v3 layout (email_layout).

The layout escapes every value it is given, so an email builder never has
to escape by hand; only the output of another layout block is markup.
"""
import asyncio
from datetime import datetime

from app.services import email_layout as e

PAYLOAD = '<a href="https://phish.invalid/login">x</a>'
ESCAPED = '&lt;a href=&quot;https://phish.invalid/login&quot;&gt;'
LAYOUT_MARK = 'class="m-bg"'


def _inert(html):
    assert '<a href="https://phish.invalid' not in html
    assert ESCAPED in html


def test_every_block_escapes_its_values():
    html = e.render(
        title=f'T{PAYLOAD}', topic=f'Topic{PAYLOAD}', intro=f'I{PAYLOAD}', footer=f'F{PAYLOAD}',
        app_title=f'App{PAYLOAD}',
        blocks=[
            e.panel(f'P{PAYLOAD}', e.kv([(f'K{PAYLOAD}', f'V{PAYLOAD}')]),
                    e.table([f'H{PAYLOAD}'], [[f'C{PAYLOAD}']]), e.panel_text(f'X{PAYLOAD}'),
                    count=f'N{PAYLOAD}', note=f'O{PAYLOAD}'),
            e.banner('warn', f'B{PAYLOAD}', f'BT{PAYLOAD}'),
            e.stats([(f'L{PAYLOAD}', f'S{PAYLOAD}', None, f'SN{PAYLOAD}')]),
            e.paragraph(f'G{PAYLOAD}'),
            e.tag(f'Tag{PAYLOAD}'), e.mono(f'M{PAYLOAD}'), e.strong(f'St{PAYLOAD}'),
        ])
    _inert(html)
    for prefix in ('T', 'Topic', 'I', 'F', 'App', 'P', 'K', 'V', 'H', 'C', 'X', 'N', 'O', 'B', 'BT',
                   'L', 'S', 'SN', 'G', 'Tag', 'M', 'St'):
        assert f'{prefix}{ESCAPED}' in html, prefix


def test_links_only_for_http_urls():
    assert '<a href="https://rbl.example.com/?q=&quot;&gt;' in e.link('Look up', 'https://rbl.example.com/?q=">')
    assert '<a' not in e.link('Look up', 'javascript:alert(1)')
    assert '<a' not in e.link('Look up', None)


def test_line_breaks_survive_escaping():
    assert 'a<br>b' in e.paragraph('a\nb')


def test_dark_mode_and_header():
    html = e.render(title='T', topic='Weekly', app_title='My Logs', when=datetime(2026, 10, 11))
    assert 'prefers-color-scheme: dark' in html
    assert 'My Logs' in html and '11 Oct 2026' in html


def _summary_data():
    return {
        'system': {'mailboxes': {'active': 3}, 'aliases': {'active': 1}, 'domains': {'active': 1}},
        'traffic': {'total_sent': 12480, 'total_received': 20, 'sent_failed': 1, 'failure_rate': 7.5},
        'storage': {'used_percent': '40%'},
        'blacklist': {'hosts': [{'hostname': 'mx1.example.com', 'status': 'listed',
                                 'results': [{'name': 'Spamhaus ZEN', 'listed': True}]},
                                {'hostname': 'mx2.example.com', 'status': 'clean', 'results': []}]},
        'top_failures': [],
        'dns_issues': [{'domain': 'example.com', 'issues': ['SPF: invalid']}],
        'queue': {'count': 0},
        'quarantine': {'count': 2},
    }


def test_weekly_summary_uses_the_layout_and_names_what_needs_a_look():
    from app.routers.reporting import build_summary_email
    subject, text, html = build_summary_email(_summary_data(), now=datetime(2026, 10, 11))
    assert subject == 'Weekly summary: 5 Oct to 11 Oct 2026'
    assert LAYOUT_MARK in html
    assert 'Failure rate' in html and 'Rating' not in html
    assert '12,480' in html
    assert 'Needs a look: 1 host on a blacklist, DNS issues on 1 domain, a failure rate of 7.5%.' in html
    # The plain-text part carries the content, not a "view in HTML" placeholder
    assert 'mx1.example.com: listed (Spamhaus ZEN)' in text
    assert 'HTML-compatible' not in text


def test_weekly_summary_with_nothing_to_report():
    from app.routers.reporting import build_summary_email
    data = _summary_data()
    data['blacklist']['hosts'] = []
    data['dns_issues'] = []
    data['traffic']['failure_rate'] = 1
    _, text, html = build_summary_email(data, now=datetime(2026, 10, 11))
    assert 'Nothing needs your attention.' in html
    assert 'No hosts are monitored' in html and 'No hosts are monitored' in text


def test_protection_rules_email(monkeypatch):
    from app import scheduler
    from app.services import notification_service
    sent = {}
    monkeypatch.setattr(notification_service, 'notify',
                        lambda subject, text, html_content=None, **kw: sent.update(subject=subject, text=text, html=html_content))
    scheduler._notify_protection(
        banned=[(f'192.0.2.1', 'r', f'Too many failures {PAYLOAD}', True)],
        failed=[('192.0.2.2', 'r', 'mailcow did not answer', True)],
        alerts=[('198.51.100.7', 'r', f'Signed in from 2 countries {PAYLOAD}')])
    assert sent['subject'] == 'Possible stolen password'
    assert LAYOUT_MARK in sent['html']
    _inert(sent['html'])
    assert 'banned 1 address and could not ban 1 address' in sent['html']


def test_dns_change_email(monkeypatch):
    from app.routers import domains
    from app.services import notification_service
    sent = {}
    monkeypatch.setattr(notification_service, 'notify',
                        lambda subject, text, html_content=None, **kw: sent.update(html=html_content, kw=kw))
    domains.notify_dns_changes('example.com', [{'type': 'SPF', 'old': 'v=spf1 -all', 'new': f'v=spf1 {PAYLOAD}'}])
    assert LAYOUT_MARK in sent['html']
    _inert(sent['html'])
    assert sent['kw'] == {'alert_type': 'dns_changes'}


def test_anomaly_alert_email():
    from app.services.anomaly_service import _alert_email_html
    html = _alert_email_html(
        'Outbound volume spike: a@example.com',
        f'Mailbox a@example.com sent 500 messages {PAYLOAD}.\n\nReview the mailbox.',
        'critical', 'volume_spike', 'a@example.com')
    assert LAYOUT_MARK in html
    _inert(html)
    assert 'Unusual sending from a@example.com' in html
    assert 'Review the mailbox.' in html


def test_dmarc_error_email():
    from app.services.dmarc_notifications import _create_html_content
    html = _create_html_content([{'email_id': '7', 'message_id': '<m@x>', 'subject': None,
                                  'error': 'Not a report'}], sync_id=3)
    assert LAYOUT_MARK in html
    assert '1 report email could not be imported' in html
    assert '(no subject)' in html and '&lt;m@x&gt;' in html


def test_smtp_abuse_operator_email(monkeypatch):
    from app.services import notification_service, smtp_abuse_service
    sent = {}
    monkeypatch.setattr(notification_service, 'notify',
                        lambda subject, text, html, recipient, alert_type: sent.update(html=html, alert_type=alert_type))
    asyncio.run(smtp_abuse_service._notify_operator_blocked(f'u{PAYLOAD}@example.com', 500, 2))
    assert LAYOUT_MARK in sent['html']
    _inert(sent['html'])
    assert sent['alert_type'] == 'security'


def test_no_emoji_in_blacklist_subjects():
    import inspect
    from app import scheduler
    source = inspect.getsource(scheduler._run_check_monitored_hosts)
    for emoji in ('⚠️', '✅', '📉'):
        assert emoji not in source
