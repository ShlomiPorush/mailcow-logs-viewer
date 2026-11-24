import time

from app.routers.smtp_abuse import (
    _EMAIL_RE,
    _MAX_EMAIL_LENGTH,
    _MAX_WHITELIST_ENTRIES,
    is_valid_email,
)

HOSTILE = "a@" + "b." * 20_000 + "@"


def test_pattern_alone_rejects_pathological_input_fast():
    start = time.perf_counter()
    assert _EMAIL_RE.match(HOSTILE) is None
    elapsed = time.perf_counter() - start
    assert elapsed < 0.5, f"regex took {elapsed:.3f}s"


def test_bulk_sized_batch_stays_fast():
    start = time.perf_counter()
    for _ in range(200):
        assert is_valid_email(HOSTILE) is False
    assert time.perf_counter() - start < 1.0


def test_over_length_address_is_rejected():
    assert is_valid_email("a" * (_MAX_EMAIL_LENGTH + 1) + "@example.com") is False


def test_valid_addresses_still_pass():
    for value in (
        "user@example.com",
        "first.last@mail.example.com",
        "user+tag@example.test",
        "a@b.co",
    ):
        assert is_valid_email(value) is True, value


def test_invalid_addresses_are_rejected():
    for value in (
        "",
        "user",
        "user@",
        "@example.com",
        "user@example",
        "user@@example.com",
        "user name@example.com",
        "user@example..com",
    ):
        assert is_valid_email(value) is False, value


def test_whitelist_entry_cap_is_defined():
    assert _MAX_WHITELIST_ENTRIES > 0
