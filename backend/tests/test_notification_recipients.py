"""The address settings take several addresses.

ADMIN_EMAIL, BLACKLIST_ALERT_EMAIL and DMARC_ERROR_EMAIL were passed to the
mail server as one address, so "a@example.com, b@example.com" was refused
(501 Bad recipient address syntax) and no notification arrived at all,
while Settings saved the value without a word.
"""
import email

import pytest
from fastapi import HTTPException

from app.routers.settings import _normalize_address_lists
from app.services import smtp_service
from app.services.smtp_service import invalid_addresses, parse_recipients, split_addresses


@pytest.fixture
def smtp(monkeypatch):
    sent = {}

    class FakeSMTP:
        def __init__(self, *a, **kw):
            pass

        def sendmail(self, sender, recipients, message):
            sent.update(recipients=recipients, message=message)

        def quit(self):
            pass

    monkeypatch.setattr(smtp_service.smtplib, 'SMTP', FakeSMTP)
    monkeypatch.setattr(type(smtp_service.settings._inner), 'notification_smtp_configured', property(lambda self: True))
    for key, value in {'smtp_relay_mode': True, 'smtp_use_ssl': False, 'smtp_use_tls': False, 'smtp_port': 25,
                       'smtp_host': 'smtp.example.com', 'smtp_from': 'logs@example.com'}.items():
        monkeypatch.setattr(smtp_service.settings._inner, key, value)
    return sent


def test_one_message_reaches_every_address(smtp):
    assert smtp_service.send_notification_email('a@example.com, b@example.org', 'S', 'text')
    assert smtp['recipients'] == ['a@example.com', 'b@example.org']
    assert email.message_from_string(smtp['message'])['To'] == 'a@example.com, b@example.org'


def test_a_single_address_works_as_before(smtp):
    assert smtp_service.send_notification_email('a@example.com', 'S', 'text')
    assert smtp['recipients'] == ['a@example.com']


def test_invalid_entries_are_skipped_not_sent(smtp):
    assert smtp_service.send_notification_email('a@example.com; not-an-address', 'S', 'text')
    assert smtp['recipients'] == ['a@example.com']
    assert not smtp_service.send_notification_email('not-an-address', 'S', 'text')


def test_parsing():
    assert split_addresses(' a@example.com ;b@example.com\n c@example.com,, ') == [
        'a@example.com', 'b@example.com', 'c@example.com']
    assert parse_recipients('a@example.com, A@example.com') == ['a@example.com']
    assert invalid_addresses('a@example.com, Admin <b@example.com>, x@y') == ['Admin', '<b@example.com>', 'x@y']
    assert parse_recipients(None) == []


def test_settings_store_addresses_separated_by_commas():
    allowed = {'admin_email': 'a@example.com;b@example.com  c@example.com', 'blacklist_alert_email': ''}
    _normalize_address_lists(allowed)
    assert allowed == {'admin_email': 'a@example.com, b@example.com, c@example.com', 'blacklist_alert_email': ''}


def test_settings_refuse_an_entry_that_is_not_an_address():
    with pytest.raises(HTTPException) as err:
        _normalize_address_lists({'dmarc_error_email': 'a@example.com, dmarc-team'})
    assert err.value.status_code == 400
    assert err.value.detail == ('Report Import Error Email: "dmarc-team" is not an email address. '
                                'Separate several addresses with commas.')
