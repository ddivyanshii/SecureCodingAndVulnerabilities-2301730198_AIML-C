from __future__ import annotations

import logging
import os
import secrets
from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
INSTANCE_DIR = BASE_DIR / "instance"
LOG_DIR = BASE_DIR / "logs"

_log = logging.getLogger(__name__)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip().isdigit():
        return default
    value = int(raw.strip())
    if not minimum <= value <= maximum:
        return default
    return value


def _resolve_secret_key(env_name: str) -> str:
    key = os.environ.get("LIBRARY_SECRET_KEY", "")
    if len(key) >= 32:
        return key
    if env_name == "production":
        raise RuntimeError(
            "LIBRARY_SECRET_KEY must be set to at least 32 characters in production."
        )
    _log.warning(
        "LIBRARY_SECRET_KEY not set - using a random per-process key. "
        "All sessions will be invalidated on restart."
    )
    return secrets.token_hex(32)


def build_config() -> dict:
    env_name = os.environ.get("LIBRARY_ENV", "development").strip().lower()
    is_prod = env_name == "production"

    return {
        "ENV_NAME": env_name,
        "SECRET_KEY": _resolve_secret_key(env_name),
        "DATABASE": os.environ.get("LIBRARY_DATABASE", str(INSTANCE_DIR / "library.db")),
        "LOG_DIR": os.environ.get("LIBRARY_LOG_DIR", str(LOG_DIR)),
        "DEBUG": False,
        "TESTING": False,
        "SESSION_COOKIE_NAME": "library_session",
        "SESSION_COOKIE_HTTPONLY": True,
        "SESSION_COOKIE_SAMESITE": "Lax",
        "SESSION_COOKIE_SECURE": _env_bool("LIBRARY_SECURE_COOKIES", is_prod),
        "PERMANENT_SESSION_LIFETIME": timedelta(hours=8),
        "SESSION_IDLE_TIMEOUT": _env_int("LIBRARY_IDLE_TIMEOUT", 15 * 60, 60, 24 * 3600),
        "SESSION_ABSOLUTE_TIMEOUT": _env_int("LIBRARY_ABSOLUTE_TIMEOUT", 8 * 3600, 300, 7 * 24 * 3600),
        "MAX_FAILED_LOGINS": 5,
        "LOCKOUT_SECONDS": 15 * 60,
        "LOGIN_RATE_LIMIT": 10,
        "LOGIN_RATE_WINDOW": 5 * 60,
        "MAX_CONTENT_LENGTH": 16 * 1024,
        "MAX_FORM_PARTS": 50,
        "MAX_BOOKS_PER_STUDENT": 3,
        "LOAN_DAYS": 14,
    }
