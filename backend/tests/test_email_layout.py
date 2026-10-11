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


def _texts(html):
    """The text between tags, one entry per text node."""
    import re
    return [t.strip() for t in re.findall(r'>([^<]+)<', html) if t.strip()]


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
    html = e.render(title='T', topic='Weekly', app_title='My Logs', when=datetime(2026, 10, 11, 9, 5))
    assert 'prefers-color-scheme: dark' in html
    assert 'My Logs' in html and '11/10/2026 09:05' in html


def test_the_date_is_in_the_app_timezone(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings._inner, 'tz', 'Asia/Jerusalem')
    assert e.local_now().utcoffset().total_seconds() in (2 * 3600, 3 * 3600)


def test_addresses_keep_the_text_colour():
    """Gmail and Outlook made the address in a title a blue underlined link of
    their own; Outlook ignores color:inherit, so the link has the text colour."""
    html = e.render(title='Sending is off for anna@example.com', topic='Security')
    assert ('Sending is off for <a href="mailto:anna@example.com" class="m-ink" '
            'style="color:#111814;text-decoration:none;">anna@example.com</a></h1>') in html
    assert '<title>Sending is off for anna@example.com</title>' in html
    banner = e.banner('fail', 'anna@example.com logged in')
    assert 'class="m-fail" style="color:#C42B1C;text-decoration:none;">anna@example.com</a>' in banner
    assert 'href="https://example.com/?q=a@example.com"' in e.link('Look up', 'https://example.com/?q=a@example.com')


def test_address_links_take_whole_addresses_only():
    html = e.paragraph('Write to anna@example.com. Message-ID <abc@mailer.invalid>, not x@y or @example.com')
    assert _texts(html) == ['Write to', 'anna@example.com', '. Message-ID &lt;', 'abc@mailer.invalid',
                            '&gt;, not x@y or @example.com']


def test_address_scan_stays_fast_on_hostile_text():
    """The text includes subjects of inbound mail. The address pattern used to
    backtrack polynomially on a long run without a valid address (CodeQL
    py/polynomial-redos); the scan is linear now."""
    import time
    hostile = ('a.' * 40000) + '@' + ('b-' * 40000) + '!'
    started = time.perf_counter()
    e.paragraph(hostile)
    e.paragraph('a' * 80000 + '@')
    assert time.perf_counter() - started < 1


def test_long_values_are_shortened_in_the_middle():
    value = 'v=DKIM1;k=rsa;p=' + 'A' * 300 + 'END'
    shown = e.mono(value, max_length=56)
    assert 'v=DKIM1;k=rsa;p=' in shown and 'END' in shown and '…' in shown
    assert len(shown.split('>', 1)[1].rsplit('<', 1)[0]) == 56


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
    assert subject == 'Weekly summary: 05/10/2026 to 11/10/2026'
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


def _run_blacklist_job(monkeypatch, listed_count, prev_listed):
    """Run the blacklist check with one host and a cached result; return what was sent."""
    from app import scheduler
    from app.services import blacklist_service, notification_service
    monkeypatch.setattr(scheduler, '_load_blacklist_hosts_worker',
                        lambda: [{'hostname': '203.0.113.25', 'source': 'transport:mx1.example.com'}])
    results = [{'name': 'Spamhaus ZEN', 'zone': 'zen.spamhaus.org', 'listed': True,
                'info_url': 'https://check.spamhaus.org/'}] if listed_count else []
    monkeypatch.setattr(blacklist_service, 'get_cached_blacklist_check',
                        lambda ip: {'listed_count': listed_count, 'total_blacklists': 50, 'results': results})
    for name in ('start_batch_scan', 'end_batch_scan', 'update_batch_status', 'mark_host_as_processed_batch'):
        monkeypatch.setattr(blacklist_service, name, lambda *a, **kw: None)
    monkeypatch.setattr(scheduler.settings._inner, 'admin_email', 'admin@example.com')
    monkeypatch.setattr(scheduler, '_blacklist_last_listed_actionable_count', prev_listed)
    sent = []
    monkeypatch.setattr(notification_service, 'notify',
                        lambda subject, text, html, recipient, alert_type: sent.append((subject, text, html, alert_type))
                        or {'email': True, 'channels_sent': 0})
    asyncio.run(scheduler._run_check_monitored_hosts(False, True))
    assert scheduler.job_status['blacklist_check']['status'] == 'success', scheduler.job_status['blacklist_check']
    return sent


def test_blacklist_job_sends_the_alert(monkeypatch):
    sent = _run_blacklist_job(monkeypatch, listed_count=1, prev_listed=0)
    assert len(sent) == 1
    subject, text, html, alert_type = sent[0]
    assert subject == 'Blacklist: 1 host is on a blacklist' and alert_type == 'blacklist'
    shown = _texts(html)
    assert LAYOUT_MARK in html and 'mx1.example.com' in shown and 'Spamhaus ZEN' in shown
    assert '  - Spamhaus ZEN (zen.spamhaus.org)' in text.splitlines()


def test_blacklist_job_sends_cleared(monkeypatch):
    sent = _run_blacklist_job(monkeypatch, listed_count=0, prev_listed=1)
    assert [s[0] for s in sent] == ['Blacklist: all hosts are clear']
    assert LAYOUT_MARK in sent[0][2] and 'All hosts are off the blacklists' in sent[0][2]


def test_blacklist_job_sends_improved(monkeypatch):
    sent = _run_blacklist_job(monkeypatch, listed_count=1, prev_listed=3)
    assert [s[0] for s in sent] == ['Blacklist: 1 host is on a blacklist', 'Blacklist: 1 host still listed (was 3)']
    assert LAYOUT_MARK in sent[1][2] and '1 host is still listed, down from 3.' in sent[1][2]


def test_sent_mail_keeps_lines_short(monkeypatch):
    """SMTP allows at most 998 characters per line. The layout writes long
    lines, and a 7bit part sent as it is was broken by the mail server in the
    middle of a tag, so Gmail showed '< /table>' as text. The parts must be
    encoded so that no line is too long and the HTML arrives unchanged."""
    import email
    from app.services import smtp_service

    sent = {}

    class FakeSMTP:
        def __init__(self, *a, **kw):
            pass

        def sendmail(self, sender, recipients, message):
            sent['message'] = message

        def quit(self):
            pass

    monkeypatch.setattr(smtp_service.smtplib, 'SMTP', FakeSMTP)
    monkeypatch.setattr(type(smtp_service.settings._inner), 'notification_smtp_configured', property(lambda self: True))
    for key, value in {'smtp_relay_mode': True, 'smtp_use_ssl': False, 'smtp_use_tls': False, 'smtp_port': 25,
                       'smtp_host': 'smtp.example.com', 'smtp_from': 'logs@example.com'}.items():
        monkeypatch.setattr(smtp_service.settings._inner, key, value)

    from app.routers.reporting import build_summary_email
    subject, text, html = build_summary_email(_summary_data(), now=datetime(2026, 10, 11))
    assert max(len(line) for line in html.splitlines()) > 998, 'the test needs a long line'
    assert smtp_service.send_notification_email('admin@example.com', subject, text, html)

    raw = sent['message']
    assert max(len(line) for line in raw.splitlines()) <= 998
    parts = {p.get_content_type(): p.get_payload(decode=True)
             for p in email.message_from_string(raw).walk() if not p.is_multipart()}
    assert parts['text/html'].decode('utf-8') == html
    assert parts['text/plain'].decode('utf-8') == text


def test_the_app_icon_travels_with_the_email():
    """The header shows the app icon; it is sent inside the email so Outlook
    and Gmail show it without loading anything from the internet."""
    import email
    from app.services.smtp_service import build_message

    assert e.app_icon(), 'the icon file is found in the repository'
    html = e.render(title='T', topic='Test')
    assert 'src="cid:app-icon"' in html
    message = email.message_from_string(build_message('a@example.com', 'b@example.com', 'S', 'text', html).as_string())
    images = [p for p in message.walk() if p.get_content_type() == 'image/png']
    assert len(images) == 1 and images[0]['Content-ID'] == '<app-icon>'
    assert images[0].get_payload(decode=True) == e.app_icon()
    plain = email.message_from_string(build_message('a@example.com', 'b@example.com', 'S', 'text', '<p>x</p>').as_string())
    assert not [p for p in plain.walk() if p.get_content_type() == 'image/png']


def test_outlook_gets_only_the_fixed_size_rounded_tag():
    """A VML shape that grows with its content does not push the next block
    down in Outlook, so panels, cards and banners overlapped there. Only the
    topic tag, which has a fixed size, is a VML shape."""
    html = e.render(title='T', topic='Topic', blocks=[
        e.panel('P', e.kv([('Severity', e.tag('Critical', 'fail'))])),
        e.banner('warn', 'What to do', 'Text'),
        e.stats([('Sent', '1')]),
    ])
    assert html.count('<v:roundrect') == 1
    assert 'mso-fit-shape-to-text' not in html
    assert 'height:15pt' in html


def test_no_emoji_in_blacklist_subjects():
    import inspect
    from app import scheduler
    source = inspect.getsource(scheduler._run_check_monitored_hosts)
    for emoji in ('⚠️', '✅', '📉'):
        assert emoji not in source
