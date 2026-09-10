"""Email validation for the SMTP abuse whitelist must stay linear-time.

The original pattern ^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$ kept the literal dot inside the
same character class as both + quantifiers, so an input built from many dotted
groups that cannot match backtracked quadratically: with the old pattern
"a@" + "b." * 8000 + "@" takes ~0.8s, and the cost grows with the square of the
length. /smtp-abuse/whitelist accepts a JSON list of addresses, so a single
authenticated request could stall the event loop.

Two independent defences are tested here: the bounded pattern itself, and the
length cap applied before matching.
"""
import time

from app.routers.smtp_abuse import (
    _EMAIL_RE,
    _MAX_EMAIL_LENGTH,
    _MAX_WHITELIST_ENTRIES,
    is_valid_email,
)

# Quadratic on the old pattern, trivially rejected by the bounded one. The
# trailing "@" (rather than whitespace) survives the .strip() the router does.
HOSTILE = "a@" + "b." * 20_000 + "@"


def test_pattern_alone_rejects_pathological_input_fast():
    start = time.perf_counter()
    assert _EMAIL_RE.match(HOSTILE) is None
    elapsed = time.perf_counter() - start
    # The old pattern needs several seconds for this input.
    assert elapsed < 0.5, f"regex took {elapsed:.3f}s"


def test_bulk_sized_batch_stays_fast():
    # A bulk request is a list; the whole list must stay cheap, not one item.
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
