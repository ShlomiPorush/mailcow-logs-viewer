"""Password hashes for local users: scrypt from the standard library.

A hash is stored as scrypt$n$r$p$salt$hash (salt and hash in base64), so a
later change of the cost keeps every stored hash readable.
"""
import base64
import binascii
import hashlib
import hmac
import secrets
import threading
from pathlib import Path
from typing import FrozenSet, Optional, Set, Tuple

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
# A core left after cutting digits and symbols off the ends is compared only when this long
# ("abc123" is judged as it is)
MIN_BASE = 4
# Digits and symbols cut from each end: up to this many, at every place within the run
MAX_CUT = 8
# Characters that are written for one another all read as one: P@ssw0rd, Pa$$w0rd, W1ll1ams
_CANON = str.maketrans({"l": "i", "1": "i", "!": "i", "|": "i", "0": "o", "@": "a", "4": "a", "3": "e",
                        "$": "s", "5": "s", "7": "t"})

_dummy: Optional[str] = None
_dummy_lock = threading.Lock()
_lists: Optional[Tuple[FrozenSet[str], FrozenSet[str]]] = None
_lists_lock = threading.Lock()


def canon(word: str) -> str:
    """word as compared: case folded, each look-alike group read as one character."""
    return word.casefold().translate(_CANON)


def _load() -> Tuple[FrozenSet[str], FrozenSet[str]]:
    """The list as published (case folded, trimmed) and in canonical form, read once from disk."""
    global _lists
    if _lists is None:
        with _lists_lock:
            if _lists is None:
                with open(COMMON_FILE, encoding="utf-8") as f:
                    words = frozenset(w for w in (line.strip().casefold() for line in f) if w)
                _lists = (words, frozenset(canon(w) for w in words))
    return _lists


def common_passwords() -> FrozenSet[str]:
    return _load()[0]


def _run(word: str, from_start: bool) -> int:
    """How many digits and symbols (anything but a letter) the word starts or ends with."""
    chars = word if from_start else reversed(word)
    count = 0
    for c in chars:
        if c.isalpha():
            break
        count += 1
    return count


def common_forms(password: str) -> Set[str]:
    """What a password is compared as, each in canonical form: itself, and every core left by
    cutting 0 to 8 digits and symbols off the start and 0 to 8 off the end (every place within
    those runs, so "123@dm1n456!" also gives "@dm1n"), when the core has 4 or more characters.
    At most 81 forms."""
    word = password.strip()
    forms = {canon(word)}
    lead = min(_run(word, True), MAX_CUT)
    trail = min(_run(word, False), MAX_CUT)
    for start in range(lead + 1):
        for cut in range(trail + 1):
            core = word[start:len(word) - cut]
            if len(core) >= MIN_BASE:
                forms.add(canon(core))
    return forms


def is_common(password: str) -> bool:
    return not _load()[1].isdisjoint(common_forms(password))


def password_problem(password: str) -> Optional[str]:
    """Why a local user's password cannot be set, or None. Checked before anything is hashed:
    8 to 256 characters, and not one of the most common passwords, also when written in another
    case, with look-alike digits and symbols, or with digits and symbols added around a common
    word (common_forms, compared in canonical form). The dialog shows how strong it is as guidance, and asks this before Save
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
