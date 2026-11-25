from tests.conftest import csrf_from, db_query, post

SQLI_PAYLOADS = ["' OR '1'='1", "' OR 1=1 --", "admin'--", "x'); DROP TABLE books;--",
                 "' UNION SELECT username, password_hash FROM users --"]


def test_login_sqli_bypass_fails(client):
    for payload in SQLI_PAYLOADS:
        token = csrf_from(client)
        r = client.post("/login", data={"username": payload, "password": payload, "csrf_token": token})
        assert r.status_code == 401, payload
        assert "Invalid username or password." in r.get_data(as_text=True)


def test_search_injection_is_treated_as_data(student, app):
    for payload in ["' OR '1'='1", "Python' --", "%' OR 1=1 --"]:
        r = student.get("/books/search", query_string={"q": payload, "field": "title"})
        body = r.get_data(as_text=True)
        assert "Engineering Mathematics" not in body, payload
    assert db_query(app, "SELECT COUNT(*) FROM books")[0][0] == 2


def test_search_field_cannot_inject_column(student):
    r = student.get("/books/search", query_string={"q": "x", "field": "title FROM users --"})
    assert r.status_code == 400


def test_like_wildcards_are_literal(student):
    body = student.get("/books/search", query_string={"q": "%", "field": "title"}).get_data(as_text=True)
    assert "Python Basics" not in body
    body = student.get("/books/search", query_string={"q": "Python", "field": "title"}).get_data(as_text=True)
    assert "Python Basics" in body


def test_drop_table_in_add_book_rejected(librarian, app):
    r = post(librarian, "/admin/addBook", {"book_code": "CS999", "title": "x'); DROP TABLE books;--",
                                          "author": "Evil", "category": "General", "quantity": "1"})
    assert r.status_code == 400
    assert db_query(app, "SELECT COUNT(*) FROM books")[0][0] == 2


def test_reflected_xss_is_escaped(student):
    r = student.get("/books/search", query_string={"q": "<script>alert(1)</script>"})
    body = r.get_data(as_text=True)
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body


def test_log_injection_neutralised(client, app):
    token = csrf_from(client)
    client.post("/login", data={"username": "bob\nFAKE LOGIN SUCCESS admin",
                                "password": "whatever1", "csrf_token": token})
    for (details_user,) in db_query(app, "SELECT username FROM audit_log"):
        assert "\n" not in (details_user or "")
