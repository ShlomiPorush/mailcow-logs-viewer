"""Seed the smoke-test database with a small, fake data set.

Runs inside the application container (cwd /app) so it uses the app's own
models: a schema change that breaks the seed fails loudly instead of the
browser pass silently testing empty pages. Every address, domain and IP is
fake: example.com/.org/.net, .test, and the RFC 5737 documentation ranges.

Usage (from smoke.sh): docker exec -i -w /app <app> python - < smoke_seed.py
"""
import hashlib
import json
from datetime import datetime, timedelta

from app.database import SessionLocal
from app import models as m

NOW = datetime.utcnow()
ago = lambda **kw: NOW - timedelta(**kw)
sha = lambda s: hashlib.sha256(s.encode()).hexdigest()

# (sender, recipient, subject, direction, final status, score, rspamd action, postfix status, dsn)
MESSAGES = [
    ('dana@example.com', 'alex@partner.test', 'Order confirmation #7734', 'outbound', 'delivered', -21.4, 'no action', 'sent', '2.0.0'),
    ('info@vendor.test', 'noa@example.org', 'Lunch on Thursday?', 'inbound', 'delivered', 1.2, 'no action', 'sent', '2.0.0'),
    ('support@example.org', 'noc@vendor.test', 'Server migration', 'outbound', 'deferred', -18.0, 'no action', 'deferred', '4.2.2'),
    ('ops@example.org', 'nobody@shop.test', 'Weekly status report', 'outbound', 'bounced', -16.3, 'no action', 'bounced', '5.1.1'),
    ('promo@newsletter.test', 'maya@example.com', 'You have won a prize', 'inbound', 'rejected', 24.0, 'reject', 'reject', '5.7.1'),
    ('billing@newsletter.test', 'sam@example.com', 'Invoice overdue', 'inbound', 'delivered', 9.1, 'add header', 'sent', '2.0.0'),
    ('hr@example.com', 'sales@example.org', 'Holiday schedule', 'internal', 'delivered', -19.9, 'no action', 'sent', '2.0.0'),
]


def seed_messages(db):
    for i, (sender, rcpt, subject, direction, final, score, action, pstatus, dsn) in enumerate(MESSAGES):
        t = ago(minutes=10 + i * 17)
        mid = f'<{20260924000000 + i}.smoke{i}@{sender.split("@")[1]}>'
        qid = f'SMOKE{i:05X}'
        key = sha(mid)
        client_ip = f'203.0.113.{20 + i}' if direction != 'inbound' else f'198.51.100.{20 + i}'
        rs = m.RspamdLog(
            time=t, message_id=mid, queue_id=qid, subject=subject, size=4096 + i * 512,
            sender_smtp=sender, sender_mime=sender, recipients_smtp=[rcpt], recipients_mime=[rcpt],
            score=score, required_score=15.0, action=action,
            symbols={'BAYES_SPAM' if score > 5 else 'BAYES_HAM': {'score': 3.0 if score > 5 else -3.0}},
            user=sender if direction != 'inbound' else None, direction=direction, ip=client_ip,
            country_code='US', country_name='United States', is_spam=score > 5, is_skipped=False,
            has_auth=direction != 'inbound', correlation_key=key, raw_data={})
        db.add(rs)
        db.flush()
        lines = [
            ('postfix/smtpd', f'{qid}: client=unknown[{client_ip}]', None),
            ('postfix/cleanup', f'{qid}: message-id={mid}', None),
            ('postfix/smtp' if direction == 'outbound' else 'postfix/lmtp',
             f'{qid}: to=<{rcpt}>, relay=mx.{rcpt.split("@")[1]}[192.0.2.10]:25, dsn={dsn}, status={pstatus}', pstatus),
        ]
        ids = []
        for j, (program, message, status) in enumerate(lines):
            pl = m.PostfixLog(
                time=t + timedelta(seconds=j), program=program, priority='info', message=message,
                queue_id=qid, message_id=mid, sender=sender, recipient=rcpt, status=status,
                relay=f'mx.{rcpt.split("@")[1]}[192.0.2.10]:25' if status else None,
                delay=0.4 if status else None, dsn=dsn if status else None, correlation_key=key, raw_data={})
            db.add(pl)
            db.flush()
            ids.append(pl.id)
        db.add(m.MessageCorrelation(
            correlation_key=key, message_id=mid, queue_id=qid, postfix_log_ids=ids, rspamd_log_id=rs.id,
            sender=sender, recipient=rcpt, subject=subject, direction=direction, final_status=final,
            dovecot_status='stored' if final == 'delivered' and direction != 'outbound' else None,
            dovecot_mailbox='INBOX' if final == 'delivered' and direction != 'outbound' else None,
            is_complete=final != 'deferred', first_seen=t, last_seen=t + timedelta(seconds=2)))


def seed_security(db):
    for i in range(8):
        ip = '198.51.100.23' if i < 5 else '203.0.113.77'
        db.add(m.NetfilterLog(
            time=ago(minutes=5 + i * 9), priority='warn',
            message=f'{ip} matched rule id 3 (warning: unknown[{ip}]: SASL LOGIN authentication failed)',
            ip=ip, rule_id=3, attempts_left=max(0, 9 - i), username='admin@example.com',
            auth_method='SASL LOGIN', action='banned' if i == 7 else 'warning',
            country_code='NL', country_name='Netherlands', raw_data={}))
    db.add(m.SecurityAlert(
        alert_type='auth_failure_burst', severity='warning', subject='admin@example.com',
        title='Burst of failed logins for admin@example.com',
        detail='38 failed logins from 198.51.100.23 in one hour.', metric_value=38, baseline_value=2))
    db.add(m.SecurityAlert(
        alert_type='volume_spike', severity='critical', subject='dana@example.com',
        title='Outbound volume spike for dana@example.com',
        detail='412 messages in 30 minutes, usual rate is 20.', metric_value=412, baseline_value=20))
    db.add(m.SMTPAbuseAction(
        email='dana@example.com', message_count=412, threshold=200, window_minutes=30,
        action='blocked', automatic=True, app_passwords_revoked=1))


def seed_dmarc(db):
    for i, (org, fail) in enumerate([('google.com', False), ('outlook.com', True)]):
        begin = int(ago(days=2 + i).timestamp())
        rep = m.DMARCReport(
            report_id=f'smoke-dmarc-{i}', domain='example.com', org_name=org, email=f'noreply-dmarc@{org}',
            begin_date=begin, end_date=begin + 86400,
            policy_published={'domain': 'example.com', 'p': 'quarantine', 'sp': 'quarantine', 'pct': '100',
                              'adkim': 'r', 'aspf': 'r'})
        db.add(rep)
        db.flush()
        db.add(m.DMARCRecord(
            dmarc_report_id=rep.id, source_ip='203.0.113.10', count=120, disposition='none',
            dkim_result='pass', spf_result='pass', header_from='example.com', envelope_from='example.com',
            auth_results={'dkim': [{'domain': 'example.com', 'result': 'pass'}],
                          'spf': [{'domain': 'example.com', 'result': 'pass'}]},
            country_code='US', country_name='United States'))
        if fail:
            db.add(m.DMARCRecord(
                dmarc_report_id=rep.id, source_ip='192.0.2.55', count=7, disposition='quarantine',
                dkim_result='fail', spf_result='fail', header_from='example.com', envelope_from='spoof.test',
                auth_results={'dkim': [{'domain': 'spoof.test', 'result': 'fail'}],
                              'spf': [{'domain': 'spoof.test', 'result': 'fail'}]},
                country_code='NL', country_name='Netherlands'))
    tls = m.TLSReport(
        report_id='smoke-tls-0', organization_name='reporter.example.net', contact_info='smtp-tls@reporter.example.net',
        policy_domain='example.com', start_datetime=ago(days=1), end_datetime=NOW, raw_json='{}')
    db.add(tls)
    db.flush()
    db.add(m.TLSReportPolicy(
        tls_report_id=tls.id, policy_type='sts', policy_domain='example.com',
        policy_string=['version: STSv1', 'mode: enforce'], mx_host=['mail.example.com'],
        successful_session_count=340, failed_session_count=2,
        failure_details=[{'result-type': 'certificate-expired', 'failed-session-count': 2}]))


def seed_mailboxes(db):
    for i, user in enumerate(['dana@example.com', 'noa@example.org', 'maya@example.com']):
        db.add(m.MailboxStatistics(
            username=user, domain=user.split('@')[1], name=user.split('@')[0].title(),
            quota=5 * 1024 ** 3, quota_used=(i + 1) * 700 * 1024 ** 2, percent_in_use=(i + 1) * 13.7,
            messages=1200 * (i + 1), active=True, last_imap_login=int(ago(hours=i + 1).timestamp()),
            last_smtp_login=int(ago(hours=i + 2).timestamp()), attributes={}))
    db.add(m.AliasStatistics(alias_address='info@example.com', goto='dana@example.com', domain='example.com',
                             primary_mailbox='dana@example.com'))
    db.add(m.AliasStatistics(alias_address='@example.org', goto='noa@example.org', domain='example.org',
                             is_catch_all=True, primary_mailbox='noa@example.org'))


def seed_status_and_lists(db):
    db.add(m.MonitoredHost(hostname='mail.example.com', source='system', active=True, last_seen=NOW))
    db.add(m.BlacklistCheck(
        server_ip='203.0.113.10', total_blacklists=2, listed_count=1, clean_count=1, status='listed',
        checked_at=ago(minutes=38),
        results=[
            {'name': 'Barracuda', 'zone': 'b.barracudacentral.org', 'info_url': '', 'status': 'listed',
             'listed': True, 'response': '127.0.0.2'},
            {'name': 'Spamhaus ZEN', 'zone': 'zen.spamhaus.org', 'info_url': '', 'status': 'clean',
             'listed': False, 'response': None},
        ]))
    db.add(m.SpamSuppression(
        email='nobody@shop.test', type='email', reason='hard_bounce', source='auto', bounce_count=1,
        hard_bounce_count=1, last_bounce_dsn='5.1.1', last_bounce_message='Recipient address rejected: user unknown',
        active=True, synced_to_rspamd=False, expires_at=NOW + timedelta(days=30)))
    db.add(m.SpamSuppression(
        email='spoof.test', type='domain', reason='manual', source='manual', notes='Known spoofing domain',
        active=True, synced_to_rspamd=False))
    rule = m.QuarantineRule(name='Release partner invoices', match_type='sender_domain', match_value='partner.test',
                            action='release', enabled=True, hit_count=3, last_hit_at=ago(hours=5))
    db.add(rule)
    db.flush()
    db.add(m.QuarantineRuleLog(rule_id=rule.id, rule_name=rule.name, action='release', quarantine_id='101',
                               sender='billing@partner.test', recipient='dana@example.com',
                               subject='Invoice 4821', matched_field='sender_domain', matched_value='partner.test'))
    db.add(m.NotificationChannel(name='Ops webhook', channel_type='webhook',
                                 config={'url': 'https://hooks.example.com/mailcow'}, enabled=False))
    for i, line in enumerate([
            'postfix/smtpd[311]: connect from unknown[198.51.100.23]',
            'postfix/smtpd[311]: warning: unknown[198.51.100.23]: SASL LOGIN authentication failed',
            'postfix/smtpd[311]: disconnect from unknown[198.51.100.23]']):
        db.add(m.RawServiceLog(service='postfix', time=ago(minutes=3 + i), message_hash=sha(line),
                               raw_data={'message': line, 'priority': 'info', 'program': 'postfix/smtpd',
                                         'time': str(int(ago(minutes=3 + i).timestamp()))}))


def main():
    db = SessionLocal()
    try:
        seed_messages(db)
        seed_security(db)
        seed_dmarc(db)
        seed_mailboxes(db)
        seed_status_and_lists(db)
        db.commit()
    finally:
        db.close()
    print(json.dumps({'seeded_messages': len(MESSAGES)}))


if __name__ == '__main__':
    main()
