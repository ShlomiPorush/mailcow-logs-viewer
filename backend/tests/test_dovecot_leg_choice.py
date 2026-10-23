"""Which delivery leg a Dovecot LMTP line belongs to when several legs share
the recipient (issue #36).

A message Rspamd rejects into quarantine and that is released later is two
legs with the same Message-ID, sender and recipient: the rejected one, which
never reached Dovecot, and the release, which Dovecot stored. The stored
verdict used to land on the first leg with that recipient, the rejected one.
"""
from datetime import datetime, timedelta

from app.models import MessageCorrelation
from app.scheduler import _leg_for_dovecot_event

RCPT = 'user@example.test'
T0 = datetime(2026, 9, 29, 10, 32, 6)


def _leg(key, status, started, recipient=RCPT):
    return MessageCorrelation(correlation_key=key, recipient=recipient, final_status=status, first_seen=started)


def test_the_released_leg_gets_the_store_not_the_rejected_one():
    rejected = _leg('rejected', 'rejected', T0)
    released = _leg('released', 'delivered', T0 + timedelta(seconds=28))
    event = {'recipient': RCPT, 'time': T0 + timedelta(seconds=28)}
    assert _leg_for_dovecot_event([rejected, released], event) is released
    # The order the legs come in does not matter
    assert _leg_for_dovecot_event([released, rejected], event) is released


def test_a_leg_still_without_a_final_status_can_take_the_store():
    rejected = _leg('rejected', 'rejected', T0)
    released = _leg('released', None, T0 + timedelta(seconds=28))
    event = {'recipient': RCPT, 'time': T0 + timedelta(seconds=29)}
    assert _leg_for_dovecot_event([rejected, released], event) is released


def test_two_deliveries_to_one_mailbox_each_get_their_own_line():
    first = _leg('first', 'delivered', T0)
    second = _leg('second', 'delivered', T0 + timedelta(minutes=10))
    assert _leg_for_dovecot_event([first, second], {'recipient': RCPT, 'time': T0 + timedelta(seconds=2)}) is first
    assert _leg_for_dovecot_event([first, second], {'recipient': RCPT, 'time': T0 + timedelta(minutes=10, seconds=2)}) is second


def test_a_single_matching_leg_is_used_as_before():
    only = _leg('only', 'rejected', T0)
    other = _leg('other', 'delivered', T0, recipient='other@example.test')
    assert _leg_for_dovecot_event([only, other], {'recipient': RCPT, 'time': T0}) is only


def test_no_recipient_and_several_legs_is_still_not_guessed():
    legs = [_leg('a', 'delivered', T0), _leg('b', 'delivered', T0, recipient='other@example.test')]
    assert _leg_for_dovecot_event(legs, {'recipient': '', 'time': T0}) is None
