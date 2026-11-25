from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

from flask import current_app

from library_app.db import get_db, transaction
from library_app.security.audit import log_event
from library_app.services import ServiceError


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def find_student_by_roll(roll_number: str) -> sqlite3.Row | None:
    return get_db().execute(
        "SELECT id, username, full_name, roll_number FROM users "
        "WHERE roll_number = ? AND role = 'student' AND is_active = 1",
        (roll_number,),
    ).fetchone()


def issue_book(*, book_code: str, roll_number: str, librarian_id: int) -> int:
    cfg = current_app.config
    with transaction() as db:
        book = db.execute(
            "SELECT id, title, available FROM books WHERE book_code = ?", (book_code,)
        ).fetchone()
        if book is None:
            raise ServiceError("No book with that code.")
        student = db.execute(
            "SELECT id FROM users WHERE roll_number = ? AND role = 'student' AND is_active = 1",
            (roll_number,),
        ).fetchone()
        if student is None:
            raise ServiceError("No active student with that roll number.")
        if book["available"] < 1:
            raise ServiceError("No copies of this book are currently available.")

        active = db.execute(
            "SELECT COUNT(*) FROM loans WHERE student_id = ? AND returned_at IS NULL",
            (student["id"],),
        ).fetchone()[0]
        if active >= cfg["MAX_BOOKS_PER_STUDENT"]:
            raise ServiceError(f"Student already has {active} books (limit {cfg['MAX_BOOKS_PER_STUDENT']}).")

        issued_at = _now()
        due_at = issued_at + timedelta(days=cfg["LOAN_DAYS"])
        try:
            cur = db.execute(
                "INSERT INTO loans (book_id, student_id, issued_by, issued_at, due_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (book["id"], student["id"], librarian_id, issued_at.isoformat(), due_at.isoformat()),
            )
        except sqlite3.IntegrityError:
            raise ServiceError("This student already has a copy of this book.") from None
        db.execute("UPDATE books SET available = available - 1 WHERE id = ? AND available > 0",
                   (book["id"],))
    log_event("BOOK_ISSUE", "SUCCESS", f"{book_code} -> {roll_number} due {due_at.date()}")
    return int(cur.lastrowid)


def return_book(*, loan_id: int, librarian_id: int) -> None:
    with transaction() as db:
        loan = db.execute(
            "SELECT l.id, l.book_id, b.book_code, u.roll_number FROM loans l "
            "JOIN books b ON b.id = l.book_id JOIN users u ON u.id = l.student_id "
            "WHERE l.id = ? AND l.returned_at IS NULL",
            (loan_id,),
        ).fetchone()
        if loan is None:
            raise ServiceError("Loan not found or already returned.")
        db.execute(
            "UPDATE loans SET returned_at = ?, returned_to = ? WHERE id = ?",
            (_now().isoformat(), librarian_id, loan_id),
        )
        db.execute(
            "UPDATE books SET available = available + 1 WHERE id = ? AND available < quantity",
            (loan["book_id"],),
        )
    log_event("BOOK_RETURN", "SUCCESS", f"{loan['book_code']} <- {loan['roll_number']}")


def loans_for_student(student_id: int) -> list[sqlite3.Row]:
    return get_db().execute(
        "SELECT l.id, b.book_code, b.title, b.author, l.issued_at, l.due_at, l.returned_at "
        "FROM loans l JOIN books b ON b.id = l.book_id "
        "WHERE l.student_id = ? ORDER BY l.returned_at IS NOT NULL, l.due_at",
        (student_id,),
    ).fetchall()


def active_loans() -> list[sqlite3.Row]:
    return get_db().execute(
        "SELECT l.id, b.book_code, b.title, u.full_name, u.roll_number, l.issued_at, l.due_at "
        "FROM loans l JOIN books b ON b.id = l.book_id JOIN users u ON u.id = l.student_id "
        "WHERE l.returned_at IS NULL ORDER BY l.due_at LIMIT 500"
    ).fetchall()


def recent_activity(limit: int = 100) -> list[sqlite3.Row]:
    limit = max(1, min(int(limit), 500))
    return get_db().execute(
        "SELECT ts, event, outcome, username, ip, details FROM audit_log ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()


def dashboard_stats() -> dict[str, int]:
    db = get_db()
    return {
        "titles": db.execute("SELECT COUNT(*) FROM books").fetchone()[0],
        "copies": db.execute("SELECT COALESCE(SUM(quantity), 0) FROM books").fetchone()[0],
        "on_loan": db.execute("SELECT COUNT(*) FROM loans WHERE returned_at IS NULL").fetchone()[0],
        "students": db.execute("SELECT COUNT(*) FROM users WHERE role = 'student'").fetchone()[0],
        "denied_24h": db.execute(
            "SELECT COUNT(*) FROM audit_log WHERE outcome != 'SUCCESS' "
            "AND ts >= strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-1 day')"
        ).fetchone()[0],
    }
