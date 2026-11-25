from __future__ import annotations

import sqlite3

from library_app.db import get_db, transaction
from library_app.security.audit import log_event
from library_app.security.validators import escape_like
from library_app.services import ServiceError

MAX_STOCK = 1000
MAX_RESULTS = 100

_SEARCH_SQL = {
    "title": "SELECT * FROM books WHERE title LIKE ? ESCAPE '\\' ORDER BY title LIMIT ?",
    "author": "SELECT * FROM books WHERE author LIKE ? ESCAPE '\\' ORDER BY title LIMIT ?",
    "book_code": "SELECT * FROM books WHERE book_code LIKE ? ESCAPE '\\' ORDER BY title LIMIT ?",
}


def search_books(column: str, term: str) -> list[sqlite3.Row]:
    sql = _SEARCH_SQL.get(column)
    if sql is None:
        raise ServiceError("Invalid search field.")
    pattern = f"%{escape_like(term)}%"
    return get_db().execute(sql, (pattern, MAX_RESULTS)).fetchall()


def list_books() -> list[sqlite3.Row]:
    return get_db().execute("SELECT * FROM books ORDER BY book_code LIMIT 500").fetchall()


def get_book(book_id: int) -> sqlite3.Row | None:
    return get_db().execute("SELECT * FROM books WHERE id = ?", (book_id,)).fetchone()


def add_book(*, book_code: str, title: str, author: str, category: str, quantity: int) -> int:
    if not 1 <= quantity <= MAX_STOCK:
        raise ServiceError(f"Quantity must be between 1 and {MAX_STOCK}.")
    try:
        cur = get_db().execute(
            "INSERT INTO books (book_code, title, author, category, quantity, available) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (book_code, title, author, category, quantity, quantity),
        )
    except sqlite3.IntegrityError:
        log_event("BOOK_ADD", "FAILURE", f"duplicate code {book_code}")
        raise ServiceError(f"A book with code {book_code} already exists.") from None
    log_event("BOOK_ADD", "SUCCESS", f"{book_code} '{title}' qty={quantity}")
    return int(cur.lastrowid)


def add_copies(book_id: int, extra: int) -> None:
    with transaction() as db:
        book = db.execute("SELECT book_code, quantity FROM books WHERE id = ?", (book_id,)).fetchone()
        if book is None:
            raise ServiceError("Book not found.")
        new_total = book["quantity"] + extra
        if extra < 1 or new_total > MAX_STOCK:
            raise ServiceError(f"Total stock cannot exceed {MAX_STOCK} copies.")
        db.execute(
            "UPDATE books SET quantity = quantity + ?, available = available + ? WHERE id = ?",
            (extra, extra, book_id),
        )
    log_event("BOOK_ADD_COPIES", "SUCCESS", f"{book['book_code']} +{extra} -> {new_total}")


def delete_book(book_id: int) -> str:
    with transaction() as db:
        book = db.execute("SELECT book_code, title FROM books WHERE id = ?", (book_id,)).fetchone()
        if book is None:
            raise ServiceError("Book not found.")
        active = db.execute(
            "SELECT COUNT(*) FROM loans WHERE book_id = ? AND returned_at IS NULL", (book_id,)
        ).fetchone()[0]
        if active:
            raise ServiceError("This book has copies on loan and cannot be removed.")
        history = db.execute("SELECT COUNT(*) FROM loans WHERE book_id = ?", (book_id,)).fetchone()[0]
        if history:
            raise ServiceError("This book has loan history and cannot be removed.")
        db.execute("DELETE FROM books WHERE id = ?", (book_id,))
    log_event("BOOK_DELETE", "SUCCESS", f"{book['book_code']} '{book['title']}'")
    return str(book["book_code"])
