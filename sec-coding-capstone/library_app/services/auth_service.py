from __future__ import annotations

import sqlite3
import time

from flask import current_app

from library_app.db import get_db
from library_app.security import passwords
from library_app.security.audit import log_event
from library_app.services import ServiceError

GENERIC_LOGIN_ERROR = "Invalid username or password."


def register_student(*, username: str, full_name: str, email: str, roll_number: str,
                     password: str) -> int:
    password_hash = passwords.hash_password(password)
    try:
        cur = get_db().execute(
            "INSERT INTO users (username, full_name, email, roll_number, password_hash, role) "
            "VALUES (?, ?, ?, ?, ?, 'student')",
            (username, full_name, email, roll_number, password_hash),
        )
    except sqlite3.IntegrityError:
        log_event("REGISTER", "FAILURE", "duplicate account details", username=username)
        raise ServiceError("An account with these details already exists.") from None
    log_event("REGISTER", "SUCCESS", "student account created", user_id=cur.lastrowid, username=username)
    return int(cur.lastrowid)


def create_librarian(*, username: str, full_name: str, email: str, password: str) -> int:
    cur = get_db().execute(
        "INSERT INTO users (username, full_name, email, roll_number, password_hash, role) "
        "VALUES (?, ?, ?, NULL, ?, 'librarian')",
        (username, full_name, email, passwords.hash_password(password)),
    )
    return int(cur.lastrowid)


def authenticate(username: str, password: str) -> int:
    cfg = current_app.config
    db = get_db()
    row = db.execute(
        "SELECT id, username, password_hash, is_active, failed_attempts, locked_until "
        "FROM users WHERE username = ?",
        (username,),
    ).fetchone()

    if row is None:
        passwords.verify_password(password, passwords.DUMMY_HASH)
        log_event("LOGIN", "FAILURE", "unknown username", username=username)
        raise ServiceError(GENERIC_LOGIN_ERROR)

    now = time.time()
    if row["locked_until"] is not None and row["locked_until"] > now:
        passwords.verify_password(password, passwords.DUMMY_HASH)
        log_event("LOGIN", "DENIED", "account locked", user_id=row["id"], username=row["username"])
        raise ServiceError(GENERIC_LOGIN_ERROR)

    if not passwords.verify_password(password, row["password_hash"]):
        attempts = row["failed_attempts"] + 1
        if attempts >= cfg["MAX_FAILED_LOGINS"]:
            db.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = ? WHERE id = ?",
                (now + cfg["LOCKOUT_SECONDS"], row["id"]),
            )
            log_event("ACCOUNT_LOCKED", "DENIED",
                      f"{attempts} consecutive failures; locked {cfg['LOCKOUT_SECONDS']}s",
                      user_id=row["id"], username=row["username"])
        else:
            db.execute("UPDATE users SET failed_attempts = ? WHERE id = ?", (attempts, row["id"]))
            log_event("LOGIN", "FAILURE", f"bad password (attempt {attempts})",
                      user_id=row["id"], username=row["username"])
        raise ServiceError(GENERIC_LOGIN_ERROR)

    if not row["is_active"]:
        log_event("LOGIN", "DENIED", "account disabled", user_id=row["id"], username=row["username"])
        raise ServiceError(GENERIC_LOGIN_ERROR)

    new_hash = passwords.hash_password(password) if passwords.needs_rehash(row["password_hash"]) else None
    db.execute(
        "UPDATE users SET failed_attempts = 0, locked_until = NULL, "
        "password_hash = COALESCE(?, password_hash) WHERE id = ?",
        (new_hash, row["id"]),
    )
    log_event("LOGIN", "SUCCESS", "", user_id=row["id"], username=row["username"])
    return int(row["id"])
