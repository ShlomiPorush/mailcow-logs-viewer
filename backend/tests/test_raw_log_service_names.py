"""
The raw log services setting is free text; only known mailcow services may
come out of it, because the names go into mailcow API paths and the Logs page.
"""
import pytest

from app.config import ALL_RAW_LOG_SERVICES, settings


def services(value):
    return settings._inner.model_copy(update={"raw_logs_services": value}).raw_logs_services_list


def test_known_services_are_kept_in_order():
    assert services("postfix, Dovecot,sogo") == ["postfix", "dovecot", "sogo"]


def test_unknown_names_are_dropped():
    assert services("postfix,x'\"><b>,../../api/v1/edit,dovecot") == ["postfix", "dovecot"]


def test_repeats_are_listed_once():
    assert services("postfix,postfix,dovecot") == ["postfix", "dovecot"]


@pytest.mark.parametrize("value", ["all", " ALL "])
def test_all_means_every_service(value):
    assert services(value) == list(ALL_RAW_LOG_SERVICES)


@pytest.mark.parametrize("value", ["", "nothing-known"])
def test_nothing_known_means_no_services(value):
    assert services(value) == []
