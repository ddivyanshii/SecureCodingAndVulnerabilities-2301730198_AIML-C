from __future__ import annotations

import secrets
import sqlite3

from library_app.db import get_db
from library_app.security import validators as v
from library_app.services import ServiceError, auth_service, book_service

DEMO_BOOKS = [
    ("CS101", "Python Basics", "Guido Rossum", "Computer Science", 5),
    ("CS102", "Data Structures in C", "Mark Allen Weiss", "Computer Science", 3),
    ("CS201", "Secure Coding in C and C++", "Robert Seacord", "Computer Science", 2),
    ("CS305", "Machine Learning Fundamentals", "Tom Mitchell", "Computer Science", 4),
    ("MATH101", "Engineering Mathematics", "B S Grewal", "Mathematics", 6),
    ("EC110", "Digital Electronics", "Morris Mano", "Electronics", 3),
    ("PHY120", "Concepts of Physics", "H C Verma", "Physics", 4),
    ("MGT200", "Principles of Management", "Peter Drucker", "Management", 1),
]


def _random_password() -> str:
    return secrets.token_urlsafe(12) + "7a"


def seed_demo(password: str | None = None) -> list[str]:
    out: list[str] = []
    if password is not None:
        v.validate_password(password)
    get_db()

    librarian_pw = password or _random_password()
    try:
        auth_service.create_librarian(username="librarian1", full_name="Asha Librarian",
                                      email="librarian1@college.example", password=librarian_pw)
        out.append(f"librarian1 / {librarian_pw}   (role: librarian)")
    except sqlite3.IntegrityError:
        out.append("librarian1 already exists - skipped")

    for username, name, roll in (("student1", "Ravi Kumar", "2023CSE001"),
                                 ("student2", "Priya Sharma", "2023CSE002")):
        pw = password or _random_password()
        try:
            auth_service.register_student(username=username, full_name=name,
                                          email=f"{username}@college.example",
                                          roll_number=roll, password=pw)
            out.append(f"{username} / {pw}   (role: student, roll {roll})")
        except ServiceError:
            out.append(f"{username} already exists - skipped")

    added = 0
    for code, title, author, cat, qty in DEMO_BOOKS:
        try:
            book_service.add_book(book_code=code, title=title, author=author, category=cat, quantity=qty)
            added += 1
        except ServiceError:
            continue
    out.append(f"{added} demo books added.")
    out.append("Store these credentials now - they are not saved anywhere in plain text.")
    return out
