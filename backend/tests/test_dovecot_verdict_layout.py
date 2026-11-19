"""The Dovecot verdict comes from the action text after the msgid field.

parse_dovecot_message ended the Message-ID at the first '>' and then looked
for action words anywhere in the rest of the line. Dovecot keeps a quoted
id-left verbatim, '>' and spaces included, so a sender using
Message-ID: <"legit0@partner.test>: discarded message: x"@sender.invalid>
gets a line that Dovecot itself writes as

    msgid=<legit0@partner.test>: discarded message: x@sender.invalid>: saved mail to INBOX

and the app recorded the earlier, delivered message legit0@partner.test as
discarded by Sieve.
"""
import pytest

from app.services.dovecot_parser import parse_dovecot_message

USER = 'user@example.com'


def _lmtp(rest):
    return f'lmtp({USER})<4242><SessAbc123>: {rest}'


def test_quoted_message_id_from_the_record_is_stored_not_discarded():
    parsed = parse_dovecot_message(_lmtp(
        'msgid=<legit0@partner.test>: discarded message: x@sender.invalid>: saved mail to INBOX'))
    assert parsed['verdict'] == 'stored'
    assert parsed['mailbox'] == 'INBOX'
    assert parsed['message_id'] == 'legit0@partner.test>: discarded message: x@sender.invalid'


@pytest.mark.parametrize('fake_action', [
    'discarded message',
    'rejected message from <a@sender.invalid> (spam)',
    'forwarded to <other@sender.invalid>',
    'marked message to be discarded if not explicitly delivered (discard action)',
    'save failed to INBOX: Quota exceeded',
    "failed to store into mailbox 'INBOX': Quota exceeded",
])
@pytest.mark.parametrize('real_action, mailbox', [
    ("sieve: msgid=<{mid}>: stored mail into mailbox 'Junk'", 'Junk'),
    ('msgid=<{mid}>: saved mail to INBOX', 'INBOX'),
])
def test_no_action_text_inside_the_message_id_wins_over_the_real_action(fake_action, real_action, mailbox):
    mid = f'legit0@partner.test>: {fake_action}: x@sender.invalid'
    parsed = parse_dovecot_message(_lmtp(real_action.format(mid=mid)))
    assert parsed['verdict'] == 'stored'
    assert parsed['mailbox'] == mailbox
    assert parsed['message_id'] != 'legit0@partner.test'


def test_a_genuine_discard_is_still_a_discard():
    parsed = parse_dovecot_message(_lmtp('sieve: msgid=<m@d>: discarded message'))
    assert parsed['verdict'] == 'discarded'
    assert parsed['message_id'] == 'm@d'


def test_unknown_action_text_is_not_a_verdict():
    assert parse_dovecot_message(_lmtp('msgid=<m@d>: something else entirely')) is None
