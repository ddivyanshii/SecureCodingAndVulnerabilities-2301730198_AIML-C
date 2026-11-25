from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass

from flask import current_app, g, session

from library_app.db import get_db
from library_app.security.audit import client_ip, log_event


@dataclass(frozen=True)
class CurrentUser:
    id: int
    username: str
    full_name: str
    role: str
    roll_number: str | None

    @property
    def is_librarian(self) -> bool:
        return self.role == "librarian"

    @property
    def is_student(self) -> bool:
        return self.role == "student"


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(user_id: int) -> None:
    token = secrets.token_urlsafe(32)
    now = time.time()
    get_db().execute(
        "INSERT INTO sessions (token_hash, user_id, created_at, last_seen, ip) VALUES (?, ?, ?, ?, ?)",
        (_hash_token(token), user_id, now, now, client_ip()),
    )
    session.clear()
    session["sid"] = token
    session["csrf"] = secrets.token_urlsafe(32)
    session.permanent = True


def destroy_session() -> None:
    token = session.get("sid")
    if isinstance(token, str):
        get_db().execute("DELETE FROM sessions WHERE token_hash = ?", (_hash_token(token),))
    session.clear()


def destroy_all_sessions(user_id: int) -> None:
    get_db().execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))


def load_current_user() -> None:
    g.user = None
    g.session_expired = False
    token = session.get("sid")
    if not isinstance(token, str) or not token:
        return

    db = get_db()
    token_hash = _hash_token(token)
    row = db.execute(
        "SELECT s.created_at, s.last_seen, u.id, u.username, u.full_name, u.role, "
        "       u.roll_number, u.is_active "
        "FROM sessions s JOIN users u ON u.id = s.user_id "
        "WHERE s.token_hash = ?",
        (token_hash,),
    ).fetchone()

    if row is None:
        session.clear()
        return

    now = time.time()
    idle = now - row["last_seen"]
    age = now - row["created_at"]
    cfg = current_app.config
    if idle > cfg["SESSION_IDLE_TIMEOUT"] or age > cfg["SESSION_ABSOLUTE_TIMEOUT"]:
        db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
        session.clear()
        g.session_expired = True
        log_event("SESSION_TIMEOUT", "SUCCESS", f"idle={int(idle)}s age={int(age)}s",
                  user_id=row["id"], username=row["username"])
        return

    if not row["is_active"]:
        db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
        session.clear()
        return

    db.execute("UPDATE sessions SET last_seen = ? WHERE token_hash = ?", (now, token_hash))
    g.user = CurrentUser(
        id=row["id"],
        username=row["username"],
        full_name=row["full_name"],
        role=row["role"],
        roll_number=row["roll_number"],
    )


def purge_expired_sessions() -> int:
    cfg = current_app.config
    now = time.time()
    cur = get_db().execute(
        "DELETE FROM sessions WHERE last_seen < ? OR created_at < ?",
        (now - cfg["SESSION_IDLE_TIMEOUT"], now - cfg["SESSION_ABSOLUTE_TIMEOUT"]),
    )
    return cur.rowcount
