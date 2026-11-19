"""An Exact Match rule ignores letter case on every field, the subject included."""
from types import SimpleNamespace

from app.routers.quarantine_rules import _find_matching_rule


def _rule(match_type, value):
    return SimpleNamespace(id=1, name="Exact", match_type=match_type, match_value=value,
                           is_regex=False, action="release", enabled=True)


def test_exact_subject_matches_regardless_of_case():
    rule = _rule("subject", "Invoice Ready")
    for subject in ("Invoice Ready", "INVOICE READY", "invoice ready"):
        assert _find_matching_rule([rule], "user@example.com", "example.com",
                                   "rcpt@example.org", subject) is rule


def test_exact_subject_still_needs_the_whole_value():
    rule = _rule("subject", "Invoice Ready")
    assert _find_matching_rule([rule], "user@example.com", "example.com",
                               "rcpt@example.org", "Your Invoice Ready now") is None


def test_exact_sender_with_mixed_case_value():
    # The job lowercases sender and recipient before matching
    rule = _rule("sender", "NoReply@Example.com")
    assert _find_matching_rule([rule], "noreply@example.com", "example.com",
                               "rcpt@example.org", "Hello") is rule
