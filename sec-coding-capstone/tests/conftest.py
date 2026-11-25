from __future__ import annotations

import re

import pytest

from library_app import create_app
from library_app.services import auth_service, book_service

LIB_PW = "Librarian#2026"
STU_PW = "Student#2026"
STU2_PW = "Student2#2026"


@pytest.fixture()
def app(tmp_path):
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-secret-key-" + "x" * 32,
        "DATABASE": str(tmp_path / "test.db"),
        "LOG_DIR": str(tmp_path / "logs"),
    })
    with app.app_context():
        auth_service.create_librarian(username="librarian1", full_name="Asha Librarian",
                                      email="lib@college.example", password=LIB_PW)
        auth_service.register_student(username="student1", full_name="Ravi Kumar",
                                      email="s1@college.example", roll_number="2023CSE001",
                                      password=STU_PW)
        auth_service.register_student(username="student2", full_name="Priya Sharma",
                                      email="s2@college.example", roll_number="2023CSE002",
                                      password=STU2_PW)
        book_service.add_book(book_code="CS101", title="Python Basics", author="Guido Rossum",
                              category="Computer Science", quantity=2)
        book_service.add_book(book_code="MATH101", title="Engineering Mathematics",
                              author="B S Grewal", category="Mathematics", quantity=1)
    yield app


@pytest.fixture()
def client(app):
    return app.test_client()


def csrf_from(client) -> str:
    for url in ("/login", "/books/search"):
        html = client.get(url).get_data(as_text=True)
        match = re.search(r'name="csrf_token" value="([^"]+)"', html)
        if match:
            return match.group(1)
    raise AssertionError("CSRF token not found in page")


def login(client, username: str, password: str, *, follow: bool = False):
    token = csrf_from(client)
    return client.post("/login", data={"username": username, "password": password,
                                       "csrf_token": token}, follow_redirects=follow)


def post(client, url: str, data: dict | None = None, **kw):
    payload = dict(data or {})
    payload["csrf_token"] = csrf_from(client)
    return client.post(url, data=payload, **kw)


@pytest.fixture()
def librarian(client):
    assert login(client, "librarian1", LIB_PW).status_code == 302
    return client


@pytest.fixture()
def student(client):
    assert login(client, "student1", STU_PW).status_code == 302
    return client


def db_query(app, sql: str, params: tuple = ()):
    from library_app.db import get_db

    with app.app_context():
        return get_db().execute(sql, params).fetchall()
