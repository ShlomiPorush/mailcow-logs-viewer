"""Protection rules: which log lines count as a successful login.

A successful login exempts an address from the unknown-accounts rule and is
what the breach alert reports. Only the line the server writes for a login
counts: smtpd's "client=..., sasl_method=..., sasl_username=..." line and
Dovecot's "<service>-login: Login: user=<...>" line, read from their start.
Postfix also logs text a client sends (a rejected command), and Dovecot logs
the user name a failed login typed, so the same words elsewhere in a line
prove nothing.
"""
import uuid
from datetime import datetime, timedelta

import pytest

from test_protection_rules import (  # noqa: F401  (db is a fixture)
    DOMAIN, MARKER, SPRAY_IP, TRAP_IP, TYPO_IP, _context, _fail, _hits, _rules, db,
)


@pytest.fixture()
def raw(db):
    from app.models import RawServiceLog
    yield
    db.query(RawServiceLog).filter(RawServiceLog.message_hash.like(f'{MARKER}%')).delete(synchronize_session=False)
    db.commit()


def _postfix(session, message, program='postfix/smtpd', minutes_ago=60):
    from app.models import PostfixLog
    session.add(PostfixLog(time=datetime.utcnow() - timedelta(minutes=minutes_ago), queue_id=MARKER[:20],
                           program=program, message=message))
    session.commit()


def _dovecot(session, message, minutes_ago=60):
    from app.models import RawServiceLog
    session.add(RawServiceLog(service='dovecot', time=datetime.utcnow() - timedelta(minutes=minutes_ago),
                              message_hash=f'{MARKER}-{uuid.uuid4().hex}',
                              raw_data={'program': 'dovecot', 'priority': 'info', 'message': message}))
    session.commit()


def _three_unknown(session, ip):
    _rules(session, unknown_accounts={'enabled': True, 'threshold': 3, 'window_minutes': 60})
    for name in ('inof', 'ifno', 'nifo'):
        _fail(session, ip, name)


def _caught(session):
    return [(h.ip, h.rule) for h in _hits(session)]


# ---------- what the client sent is not a login ----------

def test_a_rejected_command_naming_its_own_address_does_not_exempt_it(db):
    from app.services import protection_rules
    _postfix(db, f'warning: non-SMTP command from unknown[{SPRAY_IP}]: GET / client=x[{SPRAY_IP}], '
                 f'sasl_method=PLAIN, sasl_username=info@{DOMAIN}')
    _three_unknown(db, SPRAY_IP)
    protection_rules.evaluate(db, _context())
    assert _caught(db) == [(SPRAY_IP, 'unknown_accounts')]


def test_a_rejected_command_naming_another_address_does_not_exempt_that_one(db):
    from app.services import protection_rules
    _postfix(db, f'warning: non-SMTP command from unknown[{TRAP_IP}]: POST / {MARKER[:10]}: '
                 f'client=unknown[{SPRAY_IP}], sasl_method=PLAIN, sasl_username=info@{DOMAIN}')
    _three_unknown(db, SPRAY_IP)
    protection_rules.evaluate(db, _context())
    assert _caught(db) == [(SPRAY_IP, 'unknown_accounts')]


def test_a_failed_imap_login_whose_user_name_looks_like_a_login_does_not_exempt(db, raw):
    from app.services import protection_rules
    _dovecot(db, f'imap-login: Disconnected (auth failed, 1 attempts in 2 secs): '
                 f'user=<Login: user=<info@{DOMAIN}>, rip={SPRAY_IP},>, method=PLAIN, rip={TRAP_IP}, '
                 f'lip=172.22.1.250, TLS')
    _three_unknown(db, SPRAY_IP)
    protection_rules.evaluate(db, _context())
    assert _caught(db) == [(SPRAY_IP, 'unknown_accounts')]


def test_a_rejected_command_does_not_raise_a_breach_alert(db):
    from app.services import protection_rules
    _rules(db, breach={'enabled': True, 'failures': 3, 'window_minutes': 60, 'new_country': False})
    protection_rules.evaluate(db, _context())  # starts reading the logins from now
    for _ in range(3):
        _fail(db, SPRAY_IP, f'info@{DOMAIN}', minutes_ago=10)
    _postfix(db, f'warning: non-SMTP command from unknown[{TRAP_IP}]: GET / {MARKER[:10]}: '
                 f'client=unknown[{SPRAY_IP}], sasl_method=LOGIN, sasl_username=info@{DOMAIN}', minutes_ago=0)
    protection_rules.evaluate(db, _context())
    assert _hits(db) == []


def test_a_failed_imap_login_does_not_raise_a_breach_alert(db, raw):
    from app.services import protection_rules
    from app.services.protection_rules import ProtectionContext
    context = ProtectionContext(raw_logs=True)
    _rules(db, breach={'enabled': True, 'failures': 3, 'window_minutes': 60, 'new_country': False})
    protection_rules.evaluate(db, context)
    for _ in range(3):
        _fail(db, SPRAY_IP, f'info@{DOMAIN}', minutes_ago=10)
    _dovecot(db, f'imap-login: Disconnected (auth failed, 1 attempts in 2 secs): '
                 f'user=<Login: user=<info@{DOMAIN}>, rip={SPRAY_IP},>, method=PLAIN, rip={TRAP_IP}, '
                 f'lip=172.22.1.250, TLS', minutes_ago=0)
    protection_rules.evaluate(db, context)
    assert _hits(db) == []


# ---------- the server's own login lines still count ----------

def test_a_real_imap_login_exempts_the_address(db, raw):
    from app.services import protection_rules
    _dovecot(db, f'imap-login: Login: user=<info@{DOMAIN}>, method=PLAIN, rip={TYPO_IP}, lip=172.22.1.250, '
                 f'mpid=4242, TLS, session=<AbCdEf>')
    _three_unknown(db, TYPO_IP)
    protection_rules.evaluate(db, _context())
    assert _hits(db) == []


def test_a_real_login_behind_many_lines_that_only_look_like_one_still_counts(db):
    from app.models import PostfixLog
    from app.services import protection_rules
    since = datetime.utcnow() - timedelta(hours=3)
    db.bulk_save_objects([PostfixLog(
        time=since, queue_id=MARKER[:20], program='postfix/smtpd',
        message=f'warning: non-SMTP command from unknown[{TYPO_IP}]: GET / client=x[{TYPO_IP}], '
                f'sasl_method=PLAIN, sasl_username=n{n}@{DOMAIN}') for n in range(1200)])
    db.commit()
    _postfix(db, f'4Fq2Lk7Xz: client=unknown[{TYPO_IP}]:52814, sasl_method=PLAIN, sasl_username=info@{DOMAIN}',
             program='postfix/submission/smtpd')
    _three_unknown(db, TYPO_IP)
    protection_rules.evaluate(db, _context())
    assert _hits(db) == []


# ---------- line shapes ----------

@pytest.mark.parametrize('program,message,expected', [
    ('postfix/smtpd', 'ABC123DEF: client=unknown[192.0.2.7], sasl_method=PLAIN, sasl_username=a@example.com',
     ('192.0.2.7', 'a@example.com')),
    ('postfix/submission/smtpd', '4Xb9Kq1zTz: client=mail.example.com[2001:db8::7]:5870, sasl_method=LOGIN, '
     'sasl_username=A@Example.com, sasl_sender=b@example.com', ('2001:db8::7', 'a@example.com')),
    ('postfix/smtps/smtpd', 'ABC123DEF: client=unknown[IPv6:2001:db8::8], sasl_method=PLAIN, sasl_username=a@example.com',
     ('2001:db8::8', 'a@example.com')),
    # a rejected command that carries the words
    ('postfix/smtpd', 'warning: non-SMTP command from unknown[192.0.2.9]: GET / ABC: client=x[192.0.2.7], '
     'sasl_method=PLAIN, sasl_username=a@example.com', None),
    # the right words from a program that does not log logins
    ('postfix/cleanup', 'ABC123DEF: client=unknown[192.0.2.7], sasl_method=PLAIN, sasl_username=a@example.com', None),
    ('postfix/smtpd', 'ABC123DEF: client=unknown[192.0.2.7]', None),
])
def test_an_smtp_login_line_is_read_only_in_the_shape_smtpd_writes_it(program, message, expected):
    from app.services.protection_rules import _postfix_login
    assert _postfix_login(program, message) == expected


@pytest.mark.parametrize('message,expected', [
    ('imap-login: Login: user=<a@example.com>, method=PLAIN, rip=192.0.2.7, lip=172.22.1.250, mpid=1, TLS, '
     'session=<x>', ('192.0.2.7', 'a@example.com')),
    ('dovecot: pop3-login: Login: user=<A@example.com>, method=PLAIN, rip=2001:db8::7, lip=2001:db8::1, mpid=2, '
     'TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)', ('2001:db8::7', 'a@example.com')),
    ('imap-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<Login: user=<a@example.com>, '
     'rip=192.0.2.7,>, method=PLAIN, rip=192.0.2.9, lip=172.22.1.250, TLS', None),
    ('imap(a@example.com)<1><x>: Login: user=<a@example.com>, method=PLAIN, rip=192.0.2.7,', None),
])
def test_an_imap_login_line_is_read_only_in_the_shape_dovecot_writes_it(message, expected):
    from app.services.protection_rules import _dovecot_login
    assert _dovecot_login(message) == expected
