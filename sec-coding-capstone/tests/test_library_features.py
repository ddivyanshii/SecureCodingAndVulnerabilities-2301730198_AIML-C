from tests.conftest import db_query, post


def available(app, code):
    return db_query(app, "SELECT available FROM books WHERE book_code = ?", (code,))[0][0]


def test_add_book_and_search(librarian, app):
    r = post(librarian, "/admin/addBook", {"book_code": "cs201", "title": "Secure Coding in C",
                                          "author": "Robert Seacord", "category": "Computer Science",
                                          "quantity": "5"})
    assert r.status_code == 302
    row = db_query(app, "SELECT book_code, quantity, available FROM books WHERE book_code='CS201'")[0]
    assert tuple(row) == ("CS201", 5, 5)
    assert "Secure Coding in C" in librarian.get("/books/search?q=secure").get_data(as_text=True)


def test_add_book_rejects_bad_quantity_and_category(librarian, app):
    for qty in ["-5", "0", "1001", "5abc", "1e3", "999999999999999999"]:
        r = post(librarian, "/admin/addBook", {"book_code": "CS300", "title": "Some Book",
                                              "author": "Some Author", "category": "General",
                                              "quantity": qty})
        assert r.status_code == 400, qty
    r = post(librarian, "/admin/addBook", {"book_code": "CS300", "title": "Some Book",
                                          "author": "Some Author", "category": "Hacking", "quantity": "1"})
    assert r.status_code == 400
    assert db_query(app, "SELECT COUNT(*) FROM books WHERE book_code='CS300'")[0][0] == 0


def test_duplicate_book_code_rejected(librarian):
    r = post(librarian, "/admin/addBook", {"book_code": "CS101", "title": "Dup", "author": "Some Author",
                                          "category": "General", "quantity": "1"})
    assert r.status_code == 400 and "already exists" in r.get_data(as_text=True)


def test_issue_and_return_flow(librarian, app):
    assert post(librarian, "/admin/issueBook", {"book_code": "CS101", "roll_number": "2023CSE001"}).status_code == 302
    assert available(app, "CS101") == 1
    loan_id = db_query(app, "SELECT id FROM loans WHERE returned_at IS NULL")[0][0]
    assert post(librarian, "/admin/returnBook", {"loan_id": str(loan_id)}).status_code == 302
    assert available(app, "CS101") == 2
    post(librarian, "/admin/returnBook", {"loan_id": str(loan_id)})
    assert available(app, "CS101") == 2


def test_cannot_issue_when_no_copies(librarian, app):
    post(librarian, "/admin/issueBook", {"book_code": "MATH101", "roll_number": "2023CSE001"})
    r = post(librarian, "/admin/issueBook", {"book_code": "MATH101", "roll_number": "2023CSE002"})
    assert r.status_code == 400 and "No copies" in r.get_data(as_text=True)
    assert available(app, "MATH101") == 0


def test_cannot_issue_same_book_twice_to_same_student(librarian):
    post(librarian, "/admin/issueBook", {"book_code": "CS101", "roll_number": "2023CSE001"})
    r = post(librarian, "/admin/issueBook", {"book_code": "CS101", "roll_number": "2023CSE001"})
    assert r.status_code == 400


def test_max_books_per_student(librarian, app):
    for code in ("CS110", "CS111", "CS112"):
        post(librarian, "/admin/addBook", {"book_code": code, "title": f"Book {code}", "author": "Some Author",
                                          "category": "General", "quantity": "1"})
        post(librarian, "/admin/issueBook", {"book_code": code, "roll_number": "2023CSE001"})
    r = post(librarian, "/admin/issueBook", {"book_code": "CS101", "roll_number": "2023CSE001"})
    assert r.status_code == 400 and "limit" in r.get_data(as_text=True)


def test_issue_to_unknown_student(librarian):
    r = post(librarian, "/admin/issueBook", {"book_code": "CS101", "roll_number": "9999XYZ999"})
    assert r.status_code == 400 and "No active student" in r.get_data(as_text=True)


def test_cannot_delete_book_on_loan(librarian, app):
    post(librarian, "/admin/issueBook", {"book_code": "CS101", "roll_number": "2023CSE001"})
    book_id = db_query(app, "SELECT id FROM books WHERE book_code='CS101'")[0][0]
    post(librarian, "/admin/deleteBook", {"book_id": str(book_id)})
    assert db_query(app, "SELECT COUNT(*) FROM books WHERE id=?", (book_id,))[0][0] == 1


def test_delete_book(librarian, app):
    book_id = db_query(app, "SELECT id FROM books WHERE book_code='MATH101'")[0][0]
    post(librarian, "/admin/deleteBook", {"book_id": str(book_id)})
    assert db_query(app, "SELECT COUNT(*) FROM books WHERE id=?", (book_id,))[0][0] == 0
    assert "BOOK_DELETE" in [r[0] for r in db_query(app, "SELECT event FROM audit_log")]


def test_tampered_hidden_ids_rejected(librarian, app):
    for bad in ["-1", "1 OR 1=1", "abc", "99999999999999999999", ""]:
        post(librarian, "/admin/deleteBook", {"book_id": bad})
    assert db_query(app, "SELECT COUNT(*) FROM books")[0][0] == 2


def test_add_copies_respects_stock_cap(librarian, app):
    book_id = db_query(app, "SELECT id FROM books WHERE book_code='CS101'")[0][0]
    post(librarian, "/admin/addCopies", {"book_id": str(book_id), "copies": "50"})
    assert db_query(app, "SELECT quantity FROM books WHERE id=?", (book_id,))[0][0] == 52
    for bad in ["-10", "0", "101", "1e2"]:
        post(librarian, "/admin/addCopies", {"book_id": str(book_id), "copies": bad})
    assert db_query(app, "SELECT quantity FROM books WHERE id=?", (book_id,))[0][0] == 52


def test_database_constraints_are_last_line_of_defence(app):
    import sqlite3

    import pytest

    from library_app.db import get_db

    with app.app_context():
        db = get_db()
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("UPDATE books SET available = -1 WHERE book_code='CS101'")
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("UPDATE users SET role = 'superadmin' WHERE username='student1'")


def test_student_sees_own_loans(librarian, app):
    post(librarian, "/admin/issueBook", {"book_code": "CS101", "roll_number": "2023CSE001"})
    from tests.conftest import STU_PW, login

    s = app.test_client()
    login(s, "student1", STU_PW)
    assert "Python Basics" in s.get("/my-books").get_data(as_text=True)
