from __future__ import annotations

import logging
import sqlite3
from logging.handlers import RotatingFileHandler
from pathlib import Path

from flask import Flask, g, has_request_context, request

security_logger = logging.getLogger("library.security")
app_logger = logging.getLogger("library.app")

_MAX_FIELD = 300


def sanitize_for_log(value: object, max_len: int = _MAX_FIELD) -> str:
    text = "" if value is None else str(value)
    cleaned = "".join(ch if 32 <= ord(ch) != 127 else "?" for ch in text)
    return cleaned[:max_len] + ("..." if len(cleaned) > max_len else "")


def client_ip() -> str:
    if not has_request_context():
        return "-"
    return request.remote_addr or "-"


def log_event(
    event: str,
    outcome: str = "SUCCESS",
    details: str = "",
    *,
    user_id: int | None = None,
    username: str | None = None,
) -> None:
    if outcome not in ("SUCCESS", "FAILURE", "DENIED"):
        outcome = "FAILURE"
    user = g.get("user") if has_request_context() else None
    if user is not None:
        user_id = user_id if user_id is not None else user.id
        username = username if username is not None else user.username

    event_s = sanitize_for_log(event, 50)
    username_s = sanitize_for_log(username or "-", 40)
    details_s = sanitize_for_log(details)
    ip = sanitize_for_log(client_ip(), 45)

    level = logging.INFO if outcome == "SUCCESS" else logging.WARNING
    security_logger.log(
        level, "event=%s outcome=%s user=%s ip=%s details=%s",
        event_s, outcome, username_s, ip, details_s,
    )
    try:
        from library_app.db import get_db

        get_db().execute(
            "INSERT INTO audit_log (event, outcome, user_id, username, ip, details) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (event_s, outcome, user_id, username_s, ip, details_s),
        )
    except sqlite3.Error:
        app_logger.exception("Failed to write audit record")


def configure_logging(app: Flask) -> None:
    log_dir = Path(app.config["LOG_DIR"])
    log_dir.mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")

    for logger, filename in ((security_logger, "security.log"), (app_logger, "app.log")):
        logger.setLevel(logging.INFO)
        for old in [h for h in logger.handlers if getattr(h, "_library_handler", False)]:
            logger.removeHandler(old)
            old.close()
        handler = RotatingFileHandler(
            log_dir / filename, maxBytes=1_000_000, backupCount=5, encoding="utf-8", delay=True
        )
        handler.setFormatter(fmt)
        handler._library_handler = True
        logger.addHandler(handler)
