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
from typing import Optional

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

_dummy: Optional[str] = None
_dummy_lock = threading.Lock()


def password_problem(password: str) -> Optional[str]:
    """Why a local user's password cannot be set, or None. Checked before anything is hashed.
    Only its length: 8 to 256 characters (the dialog shows how strong it is, as guidance).
    The built-in admin's password (AUTH_PASSWORD) is not held to this.
    """
    if not isinstance(password, str) or len(password) < MIN_LENGTH:
        return SHORT_PROBLEM
    if len(password) > MAX_LENGTH:
        return LONG_PROBLEM
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
