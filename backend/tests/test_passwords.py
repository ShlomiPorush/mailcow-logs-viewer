"""Local users' password hashes (services/passwords.py): scrypt, bounded, constant work."""
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


WEAK = "Use at least 8 characters with an uppercase letter, a lowercase letter, a number and a symbol."


@pytest.mark.parametrize("password", [
    "Abcdef1!",                 # 8 characters, every kind once
    "Abc def1",                 # a space is a symbol
    "Ärger12€",                 # letters and a symbol outside ASCII
    "Пароль1!",                 # Cyrillic upper and lower case letters
    "A1!" + "b" * 253,          # 256 characters
])
def test_a_complex_password_of_8_to_256_characters_is_accepted(password):
    assert passwords.password_problem(password) is None


@pytest.mark.parametrize("password", [
    "Abcde1!",                  # 7 characters
    "abcdef1!",                 # no uppercase letter
    "ABCDEF1!",                 # no lowercase letter
    "Abcdefg!",                 # no number
    "Abcdefg1",                 # no symbol
    "Abcd日本12",                # letters without case are letters, not symbols
    "Abcdefg²",                 # a superscript two is a symbol, not a number
    "",
    None,
])
def test_a_password_missing_a_requirement_is_refused_in_one_sentence(password):
    assert passwords.password_problem(password) == WEAK


def test_a_password_over_256_characters_is_refused_before_hashing():
    assert passwords.password_problem("A1!" + "b" * 254) == "Use at most 256 characters."


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
