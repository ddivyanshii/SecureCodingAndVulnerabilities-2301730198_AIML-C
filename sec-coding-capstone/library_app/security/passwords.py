from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

_ALGORITHM = "scrypt"
_N = 2**14
_R = 8
_P = 1
_SALT_BYTES = 16
_KEY_BYTES = 64
_MAXMEM = 64 * 1024 * 1024

_N_RANGE = (2**12, 2**20)
_R_RANGE = (1, 32)
_P_RANGE = (1, 16)


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def _derive(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=n, r=r, p=p, maxmem=_MAXMEM, dklen=_KEY_BYTES
    )


def hash_password(password: str) -> str:
    if not isinstance(password, str) or not password:
        raise ValueError("password must be a non-empty string")
    salt = secrets.token_bytes(_SALT_BYTES)
    digest = _derive(password, salt, _N, _R, _P)
    return f"{_ALGORITHM}${_N}${_R}${_P}${_b64e(salt)}${_b64e(digest)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, n_s, r_s, p_s, salt_s, hash_s = stored.split("$")
        if algorithm != _ALGORITHM:
            return False
        n, r, p = int(n_s), int(r_s), int(p_s)
        if not (_N_RANGE[0] <= n <= _N_RANGE[1] and n & (n - 1) == 0):
            return False
        if not (_R_RANGE[0] <= r <= _R_RANGE[1] and _P_RANGE[0] <= p <= _P_RANGE[1]):
            return False
        salt, expected = _b64d(salt_s), _b64d(hash_s)
        candidate = _derive(password, salt, n, r, p)
    except (ValueError, TypeError, AttributeError):
        return False
    return hmac.compare_digest(candidate, expected)


def needs_rehash(stored: str) -> bool:
    try:
        algorithm, n_s, r_s, p_s, *_ = stored.split("$")
        return algorithm != _ALGORITHM or (int(n_s), int(r_s), int(p_s)) != (_N, _R, _P)
    except (ValueError, AttributeError):
        return True


DUMMY_HASH = hash_password(secrets.token_urlsafe(16))
