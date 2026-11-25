import pytest

from tests.conftest import db_query, post

LIBRARIAN_ONLY_GET = ["/admin/", "/admin/books", "/admin/addBook", "/admin/issueBook",
                      "/admin/loans", "/admin/activity"]
LIBRARIAN_ONLY_POST = ["/admin/deleteBook", "/admin/addBook", "/admin/addCopies",
                       "/admin/issueBook", "/admin/returnBook"]


def test_every_endpoint_declares_an_access_policy(app):
    from library_app.security.authz import policy_of

    with app.test_request_context():
        missing = [ep for ep in app.view_functions if policy_of(ep) is None]
    assert missing == []


def test_endpoint_without_policy_is_denied(app):
    @app.route("/forgot-the-decorator")
    def forgotten():
        return "secret"

    r = app.test_client().get("/forgot-the-decorator")
    assert r.status_code == 403


@pytest.mark.parametrize("url", LIBRARIAN_ONLY_GET)
def test_anonymous_redirected_to_login(client, url):
    r = client.get(url)
    assert r.status_code == 302 and "/login" in r.headers["Location"]


@pytest.mark.parametrize("url", LIBRARIAN_ONLY_GET)
def test_student_forbidden_from_librarian_pages(student, url):
    assert student.get(url).status_code == 403


@pytest.mark.parametrize("url", LIBRARIAN_ONLY_POST)
def test_student_forbidden_from_librarian_actions(student, url):
    assert post(student, url, {"book_id": "1", "loan_id": "1", "copies": "5"}).status_code == 403


def test_student_cannot_delete_book_by_typing_url(student, app):
    assert student.get("/admin/deleteBook").status_code == 405
    r = post(student, "/admin/deleteBook", {"book_id": "1"})
    assert r.status_code == 403
    assert db_query(app, "SELECT COUNT(*) FROM books WHERE id = 1")[0][0] == 1
    denied = db_query(app, "SELECT details FROM audit_log WHERE event = 'AUTHZ_DENIED'")
    assert any("/admin/deleteBook" in row[0] for row in denied)


def test_librarian_cannot_use_student_only_pages(librarian):
    assert librarian.get("/my-books").status_code == 403


def test_role_change_takes_effect_on_next_request(librarian, app):
    assert librarian.get("/admin/books").status_code == 200
    with app.app_context():
        from library_app.db import get_db
        get_db().execute("UPDATE users SET role = 'student', roll_number = 'LIB0000001' "
                         "WHERE username = 'librarian1'")
    assert librarian.get("/admin/books").status_code == 403


def test_no_idor_on_my_books(student, app, librarian_client_factory):
    lib = librarian_client_factory()
    post(lib, "/admin/issueBook", {"book_code": "MATH101", "roll_number": "2023CSE002"})
    body = student.get("/my-books?student_id=3").get_data(as_text=True)
    assert "Engineering Mathematics" not in body


@pytest.fixture()
def librarian_client_factory(app):
    from tests.conftest import LIB_PW, login

    def make():
        c = app.test_client()
        assert login(c, "librarian1", LIB_PW).status_code == 302
        return c

    return make
