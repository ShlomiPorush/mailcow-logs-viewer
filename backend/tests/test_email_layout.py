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


def test_outlook_dark_mode_gets_neutral_greys():
    # Outlook for Android turned the tinted backgrounds into similar mid
    # greys, but kept white (as its own background) and neutral dark greys.
    # Measured 2026-10-26.
    html = e.render(title='T', topic='Weekly')
    assert '[data-ogsb] .m-bg { background-color: #FFFFFF !important; }' in html
    assert '[data-ogsb] .m-panel { background-color: #202020 !important; }' in html
    assert '[data-ogsb] .m-line { border-color: #333333 !important; }' in html
    assert '[data-ogsb] .m-rule { background-color: #333333 !important; }' in html
    assert '[data-ogsb] .m-muted-bg { background-color: #333333 !important; }' in html
    # A rule on the marked element itself loses to Outlook's inline colour,
    # and Outlook drops an attribute joined to a class
    assert '[data-ogsb].' not in html and '[data-ogsc].' not in html


def _neutral(hex_colour):
    r, g, b = (hex_colour[i:i + 2] for i in (1, 3, 5))
    return r == g == b


def test_every_surface_is_a_neutral_grey():
    # Outlook for Android and Outlook on the web turn any tinted surface, light
    # or dark, into the same mid grey, and keep neutral greys. Measured
    # 2026-10-26: the old tinted panels and dark theme came out flat grey.
    import re
    light = {'BG': e.BG, 'PANEL': e.PANEL, 'LINE': e.LINE, 'muted tint': e.TONES['muted'][1], 'BAR': e.BAR}
    assert {name: c for name, c in light.items() if not _neutral(c)} == {}
    dark = re.search(r'@media \(prefers-color-scheme: dark\) \{(.*?)\n\}', e._DARK_CSS, re.S).group(1)
    surfaces = re.findall(r'\.m-(?:bg|panel|line|rule|muted-bg|bar|mark i) \{ [a-z-]+: (#[0-9A-F]{6})', dark)
    assert len(surfaces) == 7
    assert [c for c in surfaces if not _neutral(c)] == []


def test_tags_are_outlined_not_filled():
    # Outlook on the web turned every tinted tag fill into a muddy grey-brown
    # in dark mode; a border and text in the tone colour stayed clear
    for tone, (color, tint) in e.TONES.items():
        html = e.tag('Label', tone)
        assert f'border:1px solid {color};' in html and f'color:{color};' in html
        assert 'background' not in html and 'bgcolor' not in html and tint not in html
        assert f'm-{tone}-bd' in html and f'm-{tone}-bg' not in html
    topic = e.render(title='T', topic='Security', tone='fail')
    assert 'filled="f" strokecolor="#C42B1C" strokeweight="1px"' in topic and 'fillcolor=' not in topic
    for tone, dark in {'ok': '#3FCF7F', 'warn': '#F0B03F', 'fail': '#FF6B61', 'info': '#7DB3FF', 'muted': '#97A29C'}.items():
        assert f'.m-{tone}-bd {{ border-color: {dark} !important; }}' in topic


def test_the_email_is_left_to_right():
    # A client in a right-to-left language (Outlook on the web in Hebrew)
    # otherwise mirrors the email
    html = e.render(title='T', topic='Weekly')
    assert '<html lang="en" dir="ltr"' in html
    assert '<body class="m-bg" dir="ltr"' in html
    assert '<table role="presentation" class="m-bg" dir="ltr"' in html
    # Outlook on the web drops the html and body attributes; the tables keep theirs
    assert 'dir="ltr" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:600px;' in html


def test_links_the_client_adds_look_like_text_but_ours_stay_links():
    # Outlook and Gmail turn dates such as 26.10.2026 into links of their own
    html = e.render(title='T', topic='Weekly', blocks=[e.panel('P', e.panel_text(e.link('Open', 'https://example.com')))])
    assert '.m-bg a { color: inherit !important; text-decoration: none !important; }' in html
    assert 'text-decoration:underline !important;">Open</a>' in html


def test_the_date_is_in_the_app_timezone(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings._inner, 'tz', 'Asia/Jerusalem')
    assert e.local_now().utcoffset().total_seconds() in (2 * 3600, 3 * 3600)


def test_an_email_time_is_in_the_app_timezone_and_names_it(monkeypatch):
    """Emails printed the time without a zone, so a reader could not tell
    UTC from local time."""
    from datetime import timezone
    from app.config import settings
    monkeypatch.setattr(settings._inner, 'tz', 'Europe/Berlin')
    winter = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
    assert e.format_date(winter, time=True) == '15/01/2026 13:00 CET'
    assert e.format_date(datetime(2026, 7, 15, 12, 0), time=True) == '15/07/2026 14:00 CEST'
    assert e.format_date(winter) == '15/01/2026'
    # Late in the UTC evening it is already the next day in Tokyo
    monkeypatch.setattr(settings._inner, 'tz', 'Asia/Tokyo')
    assert e.format_date(datetime(2026, 1, 15, 20, 0, tzinfo=timezone.utc)) == '16/01/2026'
    html = e.render(title='T', topic='Weekly', app_title='My Logs', when=winter)
    assert '15/01/2026 21:00 JST' in html


def test_an_email_time_in_utc_says_utc(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings._inner, 'tz', '')
    assert e.format_date(datetime(2026, 1, 15, 12, 0), time=True) == '15/01/2026 12:00 UTC'


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


def test_weekly_summary_title_is_the_exact_window_it_counts(monkeypatch):
    """The counts are a rolling 7 days up to now; the title used to start at
    now - 6 days and named no time or zone."""
    from datetime import timezone
    from app.config import settings
    from app.routers.reporting import build_summary_email
    monkeypatch.setattr(settings._inner, 'tz', 'Europe/Berlin')
    data = _summary_data()
    data['traffic'].update(start_date='2026-10-19T07:00:00Z', end_date='2026-10-26T08:00:00Z')
    subject, text, html = build_summary_email(data, now=datetime(2026, 10, 26, 8, 0, 3, tzinfo=timezone.utc))
    # The window crosses the end of summer time, so each end carries its own zone
    assert subject == 'Weekly summary: 19/10/2026 09:00 CEST to 26/10/2026 09:00 CET'
    assert '19/10/2026 09:00 CEST to 26/10/2026 09:00 CET.' in text

    # Without the window in the data, it is the 7 days up to now
    data['traffic'].pop('start_date')
    data['traffic'].pop('end_date')
    subject, _, _ = build_summary_email(data, now=datetime(2026, 1, 12, 8, 0, tzinfo=timezone.utc))
    assert subject == 'Weekly summary: 05/01/2026 09:00 to 12/01/2026 09:00 CET'


def test_weekly_summary_uses_the_layout_and_names_what_needs_a_look(monkeypatch):
    from app.config import settings
    from app.routers.reporting import build_summary_email
    monkeypatch.setattr(settings._inner, 'tz', 'UTC')
    subject, text, html = build_summary_email(_summary_data(), now=datetime(2026, 10, 11))
    assert subject == 'Weekly summary: 04/10/2026 00:00 to 11/10/2026 00:00 UTC'
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
    # Without its counts the email has no chart
    assert 'Last 24 hours' not in html and 'm-bar' not in html.split('</style>', 1)[1]


def _bar_columns(html):
    """Per bar column: the heights of its cells (spacer, bar) and the bar's class and colour."""
    import re
    columns = re.findall(r'<td width="\d+%" valign="bottom".*?</table></td>', html)
    return [([int(h) for h in re.findall(r'height="(\d+)"', column)],
             re.search(r'class="(m-bar(?:-hi)?)" bgcolor="(#[0-9A-F]{6})"', column).groups())
            for column in columns]


def test_bar_chart_scales_the_bars_to_the_largest_count():
    columns = _bar_columns(e.bar_chart([0, 1, 20, 40, 3]))
    # The bar is the last cell: zero is a 1px line, a small count stays visible
    assert [heights[-1] for heights, _ in columns] == [1, 2, 40, 80, 6]
    # Every column is as tall as the tallest bar, so the bars stand on one line
    assert {sum(heights) for heights, _ in columns} == {e.BAR_MAX_HEIGHT}


def test_bar_chart_with_nothing_counted():
    columns = _bar_columns(e.bar_chart([0] * 24, highlight=[23]))
    assert len(columns) == 24
    assert all(heights[-1] == 1 and style == ('m-bar', e.BAR) for heights, style in columns)
    assert 'm-bar' not in e.bar_chart([])


def test_bar_chart_highlights_the_marked_bars():
    columns = _bar_columns(e.bar_chart([3, 5, 39, 12], highlight=[2, 3]))
    assert [style for _, style in columns] == [
        ('m-bar', '#C4C4C4'), ('m-bar', '#C4C4C4'), ('m-bar-hi', '#C42B1C'), ('m-bar-hi', '#C42B1C')]
    # A neutral grey (no tint), which the Outlook apps keep as it is
    assert e.BAR[1:3] == e.BAR[3:5] == e.BAR[5:7]


def test_bar_chart_escapes_its_text():
    html = e.render(title='T', topic='Security', blocks=[e.panel('P', e.bar_chart(
        [1, 2], [1], start=f'S{PAYLOAD}', end=f'E{PAYLOAD}', caption=f'C{PAYLOAD}'))])
    _inert(html)
    for prefix in ('S', 'E', 'C'):
        assert f'{prefix}{ESCAPED}' in html, prefix
    # The counts become heights: anything but a number is refused
    import pytest
    with pytest.raises(ValueError):
        e.bar_chart([f'1{PAYLOAD}'])


def test_bar_chart_in_dark_mode():
    html = e.render(title='T', topic='Security')
    dark = html.split('@media (prefers-color-scheme: dark)', 1)[1].split('\n}\n', 1)[0]
    assert '.m-bar { background-color: #4A4A4A !important; }' in dark
    assert '.m-bar-hi { background-color: #FF6B61 !important; }' in dark
    # Outlook for Android turns tinted colours into a flat grey: the bars get
    # a neutral grey, and the highlighted ones their red back
    assert '[data-ogsb] .m-bar { background-color: #555555 !important; }' in html
    assert '[data-ogsb] .m-bar-hi { background-color: #FF6B61 !important; }' in html


def test_anomaly_alert_email_shows_the_last_24_hours(monkeypatch):
    from app.config import settings
    from app.services.anomaly_service import AlertChart, _alert_email_html
    monkeypatch.setattr(settings._inner, 'tz', 'Europe/Berlin')
    counts = [0] * 24
    counts[5], counts[23] = 2, 39
    chart = AlertChart(counts, [23], datetime(2026, 1, 15, 12, 0), usual_rate=0.6)
    html = _alert_email_html(
        'Outbound volume spike: a@example.com',
        'Mailbox a@example.com sent 39 messages.\n\nReview the mailbox.',
        'critical', 'volume_spike', 'a@example.com', chart)
    assert 'Messages sent per hour. 39 in the last hour, usually 0.6 an hour.' in html
    # After the details, before what to do
    assert html.index('>Details<') < html.index('>Last 24 hours<') < html.index('What to do')
    # The axis: the start a day earlier, with its date; the end with its zone
    assert '>14/01/2026 13:00<' in html and '>13:00 CET<' in html
    assert [style[0] for _, style in _bar_columns(html)].count('m-bar-hi') == 1


def test_the_chart_axis_names_both_zones_across_a_clock_change(monkeypatch):
    from app.config import settings
    from app.services.anomaly_service import AlertChart, _alert_email_html
    monkeypatch.setattr(settings._inner, 'tz', 'Europe/Berlin')
    # Summer time ended at 01:00 UTC on 25/10/2026
    chart = AlertChart([1] * 24, [23], datetime(2026, 10, 25, 12, 0))
    html = _alert_email_html('T', 'What.\n\nDo.', 'warning', 'auth_failure_burst', 'a@example.com', chart)
    assert '>24/10/2026 14:00 CEST<' in html and '>13:00 CET<' in html


def test_anomaly_alert_email_for_failed_sign_ins():
    from app.services.anomaly_service import AlertChart, _alert_email_html
    counts = [0] * 22 + [4, 8]
    chart = AlertChart(counts, [22, 23], datetime(2026, 1, 15, 12, 0))
    html = _alert_email_html(
        'Authentication failure burst: a@example.com', '12 authentication failures.\n\nSecure it.',
        'warning', 'auth_failure_burst', 'a@example.com', chart)
    assert 'Failed sign-ins per hour. 12 in the last 2 hours.' in html
    assert 'usually' not in html
    assert [style[0] for _, style in _bar_columns(html)][-3:] == ['m-bar', 'm-bar-hi', 'm-bar-hi']


def test_the_usual_rate_in_words():
    from app.services.anomaly_service import _usual_rate
    assert _usual_rate(0) == 'none'
    assert _usual_rate(0.04) == 'under 0.1 an hour'
    assert _usual_rate(0.6) == '0.6 an hour'
    assert _usual_rate(2.0) == '2 an hour'
    assert _usual_rate(12.4) == '12 an hour'


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
    # Exact comparisons: CodeQL reads "host in ..." as URL sanitizing
    shown = _texts(html)
    assert LAYOUT_MARK in html
    assert any(t == 'mx1.example.com' for t in shown) and any(t == 'Spamhaus ZEN' for t in shown)
    assert any(line == '  - Spamhaus ZEN (zen.spamhaus.org)' for line in text.splitlines())


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
