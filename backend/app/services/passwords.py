"""Password hashes for local users: scrypt from the standard library.

A hash is stored as scrypt$n$r$p$salt$hash (salt and hash in base64), so a
later change of the cost keeps every stored hash readable.
"""
import base64
import binascii
import functools
import hashlib
import hmac
import secrets
import threading
from pathlib import Path
from typing import FrozenSet, Optional, Set

N = 2 ** 15
R = 8
P = 1
DKLEN = 32
SALT_BYTES = 16
# n=2**15, r=8 needs 32 MiB (128 * r * n), just over OpenSSL's default limit
MAXMEM = 64 * 1024 * 1024
MIN_LENGTH = 8
MAX_LENGTH = 256
# The same words in the Users dialog (frontend/users.js), which checks before it sends
SHORT_PROBLEM = "Use at least 8 characters."
LONG_PROBLEM = "Use at most 256 characters."
COMMON_PROBLEM = "This password is too common. Choose another one."
# The 100,000 passwords most seen in breaches (NCSC, from Have I Been Pwned), as SecLists publishes
# them (MIT; source, commit and checksum in resources/vendored.json). Read from the image: a check
# never goes to the network
COMMON_FILE = Path(__file__).resolve().parent.parent / "resources" / "ncsc_100k_passwords.txt"
# A trimmed word is compared only when this much of it is left ("abc123" is judged as it is)
MIN_BASE = 4
# Digits and symbols written for letters: P@ssw0rd, Pa$$w0rd
_LEET = str.maketrans({"@": "a", "4": "a", "0": "o", "3": "e", "$": "s", "5": "s", "7": "t", "!": "i", "|": "l"})

_dummy: Optional[str] = None
_dummy_lock = threading.Lock()


@functools.lru_cache(maxsize=1)
def common_passwords() -> FrozenSet[str]:
    """The common-password list, read once, as compared: case folded, without surrounding spaces."""
    with open(COMMON_FILE, encoding="utf-8") as f:
        return frozenset(word for word in (line.strip().casefold() for line in f) if word)


def _trim(word: str, drop, at_start: bool) -> str:
    """word without the run of characters drop() is true for at its start or end."""
    start, end = 0, len(word)
    if at_start:
        while start < end and drop(word[start]):
            start += 1
    else:
        while end > start and drop(word[end - 1]):
            end -= 1
    return word[start:end]


def _symbol(c: str) -> bool:
    return not c.isalnum()


def _not_letter(c: str) -> bool:
    return not c.isalpha()


def common_forms(password: str) -> Set[str]:
    """What a password is compared as: itself, without symbols around it, without the digits and
    symbols around a word of 4 or more letters (Summer2024!, 123password), and each of those
    with look-alike digits and symbols read as letters (1 as i, and as l)."""
    word = password.strip().casefold()
    bases = {word, _trim(word, _symbol, True), _trim(word, _symbol, False)}
    tail = _trim(word, _not_letter, False)
    for cut in (tail, _trim(word, _not_letter, True), _trim(tail, _not_letter, True)):
        if len(cut) >= MIN_BASE:
            bases.add(cut)
    forms = set()
    for base in bases:
        letters = base.translate(_LEET)
        forms.update((base, letters.replace("1", "i"), letters.replace("1", "l")))
    forms.discard("")
    return forms


def is_common(password: str) -> bool:
    return not common_passwords().isdisjoint(common_forms(password))


def password_problem(password: str) -> Optional[str]:
    """Why a local user's password cannot be set, or None. Checked before anything is hashed:
    8 to 256 characters, and not one of the most common passwords, also when written in another
    case, with look-alike digits and symbols, or with digits and symbols added around a common
    word (common_forms). The dialog shows how strong it is as guidance, and asks this before Save
    (POST /api/users/password-check). The built-in admin's password (AUTH_PASSWORD) is not held
    to this.
    """
    if not isinstance(password, str) or len(password) < MIN_LENGTH:
        return SHORT_PROBLEM
    if len(password) > MAX_LENGTH:
        return LONG_PROBLEM
    if is_common(password):
        return COMMON_PROBLEM
    return None


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _derive(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, maxmem=MAXMEM, dklen=DKLEN)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(SALT_BYTES)
    return f"scrypt${N}${R}${P}${_b64(salt)}${_b64(_derive(password, salt, N, R, P))}"


def _parse(stored: str):
    parts = (stored or "").split("$")
    if len(parts) != 6 or parts[0] != "scrypt":
        return None
    try:
        n, r, p = int(parts[1]), int(parts[2]), int(parts[3])
        salt = base64.b64decode(parts[4], validate=True)
        expected = base64.b64decode(parts[5], validate=True)
    except (ValueError, binascii.Error):
        return None
    # Only costs this app writes: a stored value can never ask for more memory or time
    if (n, r, p) != (N, R, P) or not salt or len(expected) != DKLEN:
        return None
    return salt, expected


def verify_password(password: str, stored: Optional[str]) -> bool:
    """Whether the password matches the stored hash. An unreadable hash costs a hash too."""
    parsed = _parse(stored or "")
    if parsed is None or not isinstance(password, str) or len(password) > MAX_LENGTH:
        burn(password)
        return False
    salt, expected = parsed
    return hmac.compare_digest(_derive(password, salt, N, R, P), expected)


def burn(password) -> None:
    """Spend the time of one check, for a name that has no password to check."""
    global _dummy
    with _dummy_lock:
        if _dummy is None:
            _dummy = hash_password(secrets.token_urlsafe(16))
    parsed = _parse(_dummy)
    text = password if isinstance(password, str) else ""
    hmac.compare_digest(_derive(text[:MAX_LENGTH], parsed[0], N, R, P), parsed[1])
