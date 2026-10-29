"""Local users' password hashes (services/passwords.py): scrypt, bounded, constant work; and
the rule a new password meets: 8 to 256 characters, not one of the most common passwords."""
import hashlib
import json

import pytest

from app.services import passwords


def test_a_hash_round_trips_and_names_its_parameters():
    stored = passwords.hash_password("correct horse battery")
    scheme, n, r, p, salt, digest = stored.split("$")
    assert (scheme, n, r, p) == ("scrypt", str(2 ** 15), "8", "1")
    assert salt and digest
    assert passwords.verify_password("correct horse battery", stored)


def test_a_wrong_password_does_not_match():
    stored = passwords.hash_password("correct horse battery")
    assert not passwords.verify_password("correct horse batterz", stored)


def test_the_same_password_gets_a_new_salt_each_time():
    assert passwords.hash_password("correct horse battery") != passwords.hash_password("correct horse battery")


def test_a_non_ascii_password_round_trips():
    stored = passwords.hash_password("pässwörd 日本語 ok")
    assert passwords.verify_password("pässwörd 日本語 ok", stored)


SHORT = "Use at least 8 characters."


@pytest.mark.parametrize("password", [
    "qzxkvbnw",                 # 8 characters of one kind: no character classes are required
    "73915846",
    "Abcdef1!",
    "Kp7m-Rx4Tq9wZb2n",         # as Generate makes them
    "日本語のパスワード",           # 9 characters outside ASCII
    "\U0001F600" * 8,           # 8 characters, each outside the BMP
    "A1!" + "b" * 253,          # 256 characters
])
def test_a_password_of_8_to_256_characters_is_accepted(password):
    assert passwords.password_problem(password) is None


@pytest.mark.parametrize("password", ["Abcde1!", "1234567", "", None])
def test_a_password_under_8_characters_is_refused(password):
    assert passwords.password_problem(password) == SHORT


def test_a_password_over_256_characters_is_refused_before_hashing():
    assert passwords.password_problem("A1!" + "b" * 254) == "Use at most 256 characters."


COMMON = "This password is too common. Choose another one."


@pytest.mark.parametrize("password", ["password1", "Password1", "PASSWORD1", " password1 ", "12345678", "qwertyuiop",
                                      "baseball"])
def test_a_common_password_is_refused_in_any_case_and_with_spaces_around(password):
    assert passwords.password_problem(password) == COMMON


def test_the_common_password_list_is_the_vendored_file_and_loads_once():
    manifest = json.loads((passwords.COMMON_FILE.parent / "vendored.json").read_text(encoding="utf-8"))
    entry = manifest[passwords.COMMON_FILE.name]
    assert hashlib.sha256(passwords.COMMON_FILE.read_bytes()).hexdigest() == entry["sha256"]
    licence = passwords.COMMON_FILE.parent / entry["license_file"]
    assert hashlib.sha256(licence.read_bytes()).hexdigest() == entry["license_sha256"]
    assert licence.read_text(encoding="utf-8").startswith("MIT License")
    words = passwords.common_passwords()
    assert 9_900 <= len(words) <= 10_001
    assert passwords.common_passwords() is words, "read once"
    assert all(w == w.strip().casefold() for w in words)


@pytest.mark.parametrize("stored", [
    None, "", "plain", "scrypt$1$8$1$AAAA$AAAA",
    # Costs this app never writes are refused, so a stored value cannot ask for more memory
    "scrypt$1048576$8$1$c2FsdHNhbHRzYWx0c2FsdA==$" + "A" * 44,
])
def test_an_unreadable_hash_never_matches_and_still_costs_a_hash(stored, monkeypatch):
    passwords.burn("warm up the dummy")
    calls = []
    real = passwords._derive
    monkeypatch.setattr(passwords, "_derive", lambda *a: calls.append(a[2:]) or real(*a))
    assert not passwords.verify_password("correct horse battery", stored)
    assert calls == [(passwords.N, passwords.R, passwords.P)]


def test_burn_costs_one_hash(monkeypatch):
    passwords.burn("warm up the dummy")
    calls = []
    real = passwords._derive
    monkeypatch.setattr(passwords, "_derive", lambda *a: calls.append(1) or real(*a))
    passwords.burn("anything at all")
    assert calls == [1]
