"""HTML notification emails show data as text, never as markup.

The DMARC error notification put the Subject and Message-ID of inbound rua
mail into its HTML body unescaped, so anyone able to mail the published rua
address could add links and tracking images to an operator alert sent from
the app's own address. The other HTML emails had the same pattern with less
exposed data (host names, mailbox names, DNS issue text).
"""
import asyncio

import pytest

PAYLOAD = '<a href="https://phish.invalid/login">Re-enter password</a><img src="https://track.invalid/p.gif">'


def _assert_inert(html):
    assert '<a href="https://phish.invalid' not in html
    assert '<img src="https://track.invalid' not in html
    assert '&lt;a href=&quot;https://phish.invalid/login&quot;&gt;' in html


def test_dmarc_error_notification_escapes_inbound_fields():
    from app.services.dmarc_notifications import _create_html_content
    html = _create_html_content([{
        'email_id': '7<b>',
        'message_id': '<x"><b>MID</b>@sender.invalid>',
        'subject': f'DMARC {PAYLOAD}',
        'error': f'Not a valid DMARC or TLS-RPT report email {PAYLOAD}',
    }], sync_id=3)
    _assert_inert(html)
    assert '<b>MID</b>' not in html
    assert '&lt;b&gt;MID&lt;/b&gt;' in html


def test_weekly_summary_escapes_report_values(monkeypatch):
    from app.config import settings
    from app.routers import reporting

    async def fake_data():
        return {
            'system': {'mailboxes': {'active': 3}, 'aliases': {'active': 1}, 'domains': {'active': 1}},
            'traffic': {'total_sent': 10, 'total_received': 20, 'sent_failed': 1, 'failure_rate': 2.5},
            'storage': {'used_percent': '40%'},
            'blacklist': {'hosts': [{'hostname': f'mx{PAYLOAD}.example.com', 'status': 'listed',
                                     'results': [{'name': f'RBL {PAYLOAD}', 'listed': True}]}]},
            'top_failures': [{'username': f'user{PAYLOAD}@example.com', 'combined_failed': 1,
                              'combined_failure_rate': 5, 'combined_received': 1, 'combined_sent': 2}],
            'dns_issues': [{'domain': f'example{PAYLOAD}.com', 'issues': [f'SPF: {PAYLOAD}']}],
            'queue': {'count': 0},
            'quarantine': {'count': 0},
        }

    sent = {}
    monkeypatch.setattr(reporting, 'get_system_summary_data', fake_data)
    monkeypatch.setattr(reporting, 'send_notification_email',
                        lambda recipient, subject, text, html: sent.update(html=html))
    monkeypatch.setattr(settings._inner, 'admin_email', 'admin@example.com')
    asyncio.run(reporting.generate_and_send_email())

    assert 'html' in sent, 'the summary must be sent'
    _assert_inert(sent['html'])


def test_blacklist_alert_host_block_escapes_values():
    from app.scheduler import _blacklist_alert_host_html
    html = _blacklist_alert_host_html(
        f'mx{PAYLOAD}.example.com', f' ({PAYLOAD})', 1,
        [{'name': f'RBL {PAYLOAD}', 'zone': 'zone.example.com',
          'info_url': 'https://rbl.example.com/?q="><script>x</script>'}])
    _assert_inert(html)
    assert '<script>' not in html


def test_smtp_abuse_user_mail_escapes_the_address(monkeypatch):
    from app.config import settings
    from app.services import smtp_abuse_service, smtp_service

    sent = {}
    monkeypatch.setattr(type(settings._inner), 'notification_smtp_configured', property(lambda self: True))
    monkeypatch.setattr(settings._inner, 'smtp_abuse_help_address', f'help{PAYLOAD}@example.com')
    monkeypatch.setattr(smtp_service, 'send_notification_email',
                        lambda recipient, subject, text, html: sent.update(html=html))
    asyncio.run(smtp_abuse_service._notify_user_blocked('user@example.com', 500))

    assert 'html' in sent
    _assert_inert(sent['html'])
    assert '<br>' in sent['html'], 'line breaks still become <br>'
