import base64
import binascii
import hashlib
import hmac
import secrets
import threading
from pathlib import Path
from typing import FrozenSet, Optional

N = 2 ** 15
R = 8
P = 1
DKLEN = 32
SALT_BYTES = 16
MAXMEM = 64 * 1024 * 1024
MIN_LENGTH = 8
MAX_LENGTH = 256
SHORT_PROBLEM = "Use at least 8 characters."
LONG_PROBLEM = "Use at most 256 characters."
COMMON_PROBLEM = "This password is too common. Choose another one."
COMMON_FILE = Path(__file__).resolve().parent.parent / "resources" / "ncsc_100k_passwords.txt"

_dummy: Optional[str] = None
_dummy_lock = threading.Lock()
_common: Optional[FrozenSet[str]] = None
_common_lock = threading.Lock()


def common_passwords() -> FrozenSet[str]:
    global _common
    if _common is None:
        with _common_lock:
            if _common is None:
                with open(COMMON_FILE, encoding="utf-8") as f:
                    _common = frozenset(w for w in (line.rstrip("\n").casefold() for line in f) if w)
    return _common


def is_common(password: str) -> bool:
    return password.casefold() in common_passwords()


def password_problem(password: str) -> Optional[str]:
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
    if (n, r, p) != (N, R, P) or not salt or len(expected) != DKLEN:
        return None
    return salt, expected


def verify_password(password: str, stored: Optional[str]) -> bool:
    parsed = _parse(stored or "")
    if parsed is None or not isinstance(password, str) or len(password) > MAX_LENGTH:
        burn(password)
        return False
    salt, expected = parsed
    return hmac.compare_digest(_derive(password, salt, N, R, P), expected)


def burn(password) -> None:
    global _dummy
    with _dummy_lock:
        if _dummy is None:
            _dummy = hash_password(secrets.token_urlsafe(16))
    parsed = _parse(_dummy)
    text = password if isinstance(password, str) else ""
    hmac.compare_digest(_derive(text[:MAX_LENGTH], parsed[0], N, R, P), parsed[1])
