"""Local users' password hashes (services/passwords.py): scrypt, bounded, constant work; and
the rule a new password meets: 8 to 256 characters, not one of the most common passwords."""
import hashlib
import json
import random
import threading

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
    "Rtvqm7!k",
    "Kp7m-Rx4Tq9wZb2n",         # as Generate makes them
    "Mailcow123",               # a word not on the list, with digits
    "correct horse battery",
    "Xk7#mQ2v",
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


@pytest.mark.parametrize("password", [
    "password", "password1", "Password1", "PASSWORD1", " password1 ", "12345678", "qwertyuiop", "baseball",
    "qwerty123", "Passw0rd", "1q2w3e4r",
    # Look-alike digits and symbols, and digits or symbols around a common word
    "P@ssw0rd", "Pa$$w0rd", "Password123", "Password123!", "Aa123456", "Aa123456!", "Admin123", "admin123",
    "Welcome123", "Summer2024", "summer2024!", "123password", "!!Password!!", "p4ssw0rd99", "@dmin2025",
    # Symbols on both sides, a look-alike at the start of the word, and 1 read as i and l in one word
    "!!12345678!!", "!!abc123!!", "123@dm1n456!", "W1111ams", "Ph1111ps",
    # Runs longer than 8 around a common word: the whole run is cut too
    "123456789password123456789", "123456789admin123456789", "123456789qwerty123456789",
    "123456789williams123456789", "!!!!!!!!!!password", "password##########",
])
def test_a_common_password_is_refused_in_any_case_and_written_around(password):
    assert passwords.password_problem(password) == COMMON


def test_the_forms_a_password_is_compared_as():
    canon = passwords.canon
    # Every look-alike group reads as one character
    assert canon("P@ssw0rd") == canon("password") == "password"
    assert canon("W1111ams") == canon("williams") == canon("w!|liams")
    forms = passwords.common_forms(" Summer2024! ")
    assert {canon("summer2024!"), canon("summer2024"), canon("summer"), canon("summer2")} <= forms
    # Every place within the runs at either end, so a look-alike that starts the word is kept
    assert canon("@dm1n") in passwords.common_forms("123@dm1n456!")
    assert canon("abc123") in passwords.common_forms("!!abc123!!")
    # A core shorter than 4 is not compared on its own; the whole password is, whatever its length
    assert canon("abc") not in passwords.common_forms("abc1234567")
    assert canon("abc1234567") in passwords.common_forms("abc1234567")
    # A run longer than 8 is also cut whole, at each end and at both
    forms = passwords.common_forms("123456789password123456789")
    assert {canon("password"), canon("password123456789"), canon("123456789password")} <= forms
    # Bounded: 10 places at each end (0 to 8, and the whole run), so at most 100 forms
    assert len(passwords.common_forms("!" * 20 + "a" * 200 + "1" * 20)) == 100
    assert len(passwords.common_forms("!" * 8 + "a" * 240 + "1" * 8)) == 81


def _generated(rng, length):
    """As the Users dialog's Generate makes them (users.js usersGeneratePassword)."""
    upper, lower, digits, symbols = "ABCDEFGHJKLMNPQRSTUVWXYZ", "abcdefghijkmnpqrstuvwxyz", "23456789", "!@#$%*-_"
    count = max(1, length // 8)
    body = [rng.choice(upper), rng.choice(lower), rng.choice(digits)]
    body += [rng.choice(upper + lower + digits) for _ in range(length - count - 3)]
    rng.shuffle(body)
    while True:
        places = set(rng.sample(range(1, length - 1), count))
        if not any(i + 1 in places for i in places):
            break
    rest = iter(body)
    return "".join(rng.choice(symbols) if i in places else next(rest) for i in range(length))


def test_a_fixed_corpus_of_generated_passwords_passes():
    # Seeded, so the same passwords every run; the dialog draws a new one in the rare case the
    # server refuses a generated password
    rng = random.Random(2026)
    for length in [12] * 1000 + [20] * 50:
        password = _generated(rng, length)
        assert len(password) == length and not set(password) & set("0Oo1lI")
        assert passwords.password_problem(password) is None, password


def test_a_password_that_fits_the_generator_can_still_be_too_common():
    # Why the dialog draws again: the generator's rules allow a common word in the middle
    assert passwords.password_problem("2345Abcd%678") == COMMON


def test_the_list_is_read_once_even_when_asked_at_the_same_time(monkeypatch):
    opened = []
    real_open = open

    def counting_open(*args, **kwargs):
        opened.append(args[0])
        return real_open(*args, **kwargs)

    monkeypatch.setattr(passwords, "_lists", None)
    monkeypatch.setattr(passwords, "open", counting_open, raising=False)
    start = threading.Barrier(8)
    seen = []

    def ask():
        start.wait()
        seen.append(passwords._load())

    threads = [threading.Thread(target=ask) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(opened) == 1
    assert all(lists is seen[0] for lists in seen)


def test_the_common_password_list_is_the_vendored_file_and_loads_once():
    manifest = json.loads((passwords.COMMON_FILE.parent / "vendored.json").read_text(encoding="utf-8"))
    entry = manifest[passwords.COMMON_FILE.name]
    assert hashlib.sha256(passwords.COMMON_FILE.read_bytes()).hexdigest() == entry["sha256"]
    licence = passwords.COMMON_FILE.parent / entry["license_file"]
    assert hashlib.sha256(licence.read_bytes()).hexdigest() == entry["license_sha256"]
    assert licence.read_text(encoding="utf-8").startswith("MIT License")
    words = passwords.common_passwords()
    text = passwords.COMMON_FILE.read_text(encoding="utf-8")
    assert entry["lines"] == text.count("\n") == 99_830
    # The published file less the lines that are email addresses (no real addresses in the repository)
    assert entry["source_lines"] - entry["lines"] == 10
    assert not any("@" in line and "." in line.split("@")[-1] for line in text.splitlines())
    assert 95_000 <= len(words) <= 99_830
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
