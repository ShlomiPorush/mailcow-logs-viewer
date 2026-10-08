"""Quarantine rule regexes are bounded on sender, recipient and subject.

The values come from mail senders, so a long subject made every regex rule
scan all of it, and a pattern with nested repetition such as (a+)+ can take
exponential time and stall the single application process. Matching now looks
at the first 1000 characters only, and such patterns are refused when saved
(and skipped if one was saved before).
"""
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.routers import quarantine_rules as qr


def _rule(value, match_type="subject", action="delete", is_regex=True):
    return SimpleNamespace(id=1, name="r", match_type=match_type, match_value=value,
                           is_regex=is_regex, action=action, enabled=True)


def test_regex_only_scans_the_start_of_a_long_value():
    subject = "x" * 5000 + "needle"
    assert qr._find_matching_rule([_rule("needle")], "", "", "", subject) is None
    assert qr._find_matching_rule([_rule("needle")], "", "", "", "needle" + "x" * 5000) is not None


def test_exact_match_rules_are_not_cut():
    sender = "a" * 1200 + "@example.com"
    rule = _rule(sender, match_type="sender", is_regex=False)
    assert qr._find_matching_rule([rule], sender, "example.com", "", "") is rule


@pytest.mark.parametrize("pattern", [
    "(a+)+$",
    "(a*)*b",
    r"^(\w+\s?)+$",
    r"(?:\d+)*x",
    r"((ab)*)+c",
    r"(x+x+)+y",
    r"(.*)+@example\.com",
])
def test_nested_repetition_is_refused_on_save(pattern):
    with pytest.raises(HTTPException) as err:
        qr._validate_regex(pattern)
    assert err.value.status_code == 400
    assert "nested" in err.value.detail.lower()


@pytest.mark.parametrize("pattern", [
    r"^.*@example\.com$",
    r"([a-z0-9-]+\.)+example\.com$",
    r"(?:invoice|receipt)\s+\d+",
    r"^\[SPAM\]",
    r"(ab)+",
    r"(\d{3})+",
    r"^(re|fwd?):\s*",
    r"(?:a+)?b",
])
def test_ordinary_patterns_are_still_accepted(pattern):
    qr._validate_regex(pattern)


def test_create_rule_refuses_a_nested_repetition(monkeypatch):
    monkeypatch.setattr(qr, "_require_rw_key", lambda: None)
    body = qr.RuleCreate(name="bad", match_type="subject", match_value="(a+)+$",
                         is_regex=True, action="delete")
    with pytest.raises(HTTPException) as err:
        qr.create_rule(body)
    assert err.value.status_code == 400


def test_a_stored_nested_repetition_rule_is_skipped():
    """A rule saved before the check existed must not stall the job."""
    # The value matches, so evaluating the rule would apply it; skipping it does not
    assert qr._find_matching_rule([_rule("(a+)+$")], "", "", "", "aaaa") is None
    good = _rule("^a+$", action="release")
    assert qr._find_matching_rule([_rule("(a+)+$"), good], "", "", "", "aaaa") is good
