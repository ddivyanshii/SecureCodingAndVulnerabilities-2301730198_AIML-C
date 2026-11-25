import time

from tests.conftest import STU_PW, csrf_from, db_query, login, post


def test_register_creates_student_even_if_role_is_injected(client, app):
    token = csrf_from(client)
    r = client.post("/register", data={
        "username": "mallory", "full_name": "Mallory Hacker", "email": "m@college.example",
        "roll_number": "2023CSE099", "password": "Secure#2026", "confirm_password": "Secure#2026",
        "role": "librarian",
        "csrf_token": token,
    })
    assert r.status_code == 302
    row = db_query(app, "SELECT role, password_hash FROM users WHERE username = ?", ("mallory",))[0]
    assert row["role"] == "student"
    assert row["password_hash"].startswith("scrypt$")


def test_register_rejects_invalid_input(client):
    token = csrf_from(client)
    r = client.post("/register", data={
        "username": "x", "full_name": "R2D2", "email": "not-an-email", "roll_number": "1",
        "password": "short", "confirm_password": "short", "csrf_token": token,
    })
    assert r.status_code == 400
    body = r.get_data(as_text=True)
    assert "Only letters and single spaces" in body and "valid email" in body


def test_duplicate_registration_generic_message(client):
    token = csrf_from(client)
    r = client.post("/register", data={
        "username": "student1", "full_name": "Ravi Kumar", "email": "new@college.example",
        "roll_number": "2023CSE077", "password": "Secure#2026", "confirm_password": "Secure#2026",
        "csrf_token": token,
    })
    assert r.status_code == 400
    assert "already exists" in r.get_data(as_text=True)


def test_login_success_and_generic_failure(client):
    r = login(client, "student1", "wrong-password1")
    assert r.status_code == 401
    assert "Invalid username or password." in r.get_data(as_text=True)
    r2 = login(client, "nosuchuser", "wrong-password1")
    assert r2.get_data(as_text=True).count("Invalid username or password.") == 1
    assert login(client, "student1", STU_PW).status_code == 302


def test_account_lockout_after_five_failures(client, app):
    for _ in range(5):
        login(client, "student1", "wrong-password1")
    locked = db_query(app, "SELECT locked_until FROM users WHERE username='student1'")[0][0]
    assert locked and locked > time.time()
    r = login(client, "student1", STU_PW)
    assert r.status_code == 401
    events = [row["event"] for row in db_query(app, "SELECT event FROM audit_log")]
    assert "ACCOUNT_LOCKED" in events


def test_ip_rate_limit(app):
    app.config["LOGIN_RATE_LIMIT"] = 3
    client = app.test_client()
    codes = [login(client, f"user{i:02d}x", "wrong-password1").status_code for i in range(5)]
    assert codes[:3] == [401, 401, 401] and codes[3:] == [429, 429]


def test_session_fixation_token_rotates_on_login(client):
    csrf_from(client)
    with client.session_transaction() as sess:
        sess["sid"] = "attacker-chosen-token"
        pre_csrf = sess.get("csrf")
    login(client, "student1", STU_PW)
    with client.session_transaction() as sess:
        assert sess["sid"] != "attacker-chosen-token"
        assert sess["csrf"] != pre_csrf


def test_session_token_stored_hashed(student, app):
    with student.session_transaction() as sess:
        raw_token = sess["sid"]
    hashes = [r[0] for r in db_query(app, "SELECT token_hash FROM sessions")]
    assert raw_token not in hashes and len(hashes[0]) == 64


def test_logout_revokes_server_side_session(student, app):
    with student.session_transaction() as sess:
        stolen = dict(sess)
    assert post(student, "/logout").status_code == 302
    assert db_query(app, "SELECT COUNT(*) FROM sessions")[0][0] == 0
    with student.session_transaction() as sess:
        sess.update(stolen)
    r = student.get("/my-books")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_idle_timeout(student, app):
    with app.app_context():
        from library_app.db import get_db
        get_db().execute("UPDATE sessions SET last_seen = last_seen - ?",
                         (app.config["SESSION_IDLE_TIMEOUT"] + 1,))
    r = student.get("/my-books", follow_redirects=True)
    assert "session expired" in r.get_data(as_text=True).lower()
    assert "SESSION_TIMEOUT" in [e[0] for e in db_query(app, "SELECT event FROM audit_log")]


def test_absolute_timeout(student, app):
    with app.app_context():
        from library_app.db import get_db
        get_db().execute("UPDATE sessions SET created_at = created_at - ?",
                         (app.config["SESSION_ABSOLUTE_TIMEOUT"] + 1,))
    assert student.get("/my-books").status_code == 302


def test_disabled_account_loses_access_immediately(student, app):
    with app.app_context():
        from library_app.db import get_db
        get_db().execute("UPDATE users SET is_active = 0 WHERE username = 'student1'")
    assert student.get("/my-books").status_code == 302


def test_csrf_missing_or_wrong_token_rejected(librarian, app):
    r = librarian.post("/admin/deleteBook", data={"book_id": "1"})
    assert r.status_code == 400
    r = librarian.post("/admin/deleteBook", data={"book_id": "1", "csrf_token": "forged"})
    assert r.status_code == 400
    assert db_query(app, "SELECT COUNT(*) FROM books WHERE id = 1")[0][0] == 1


def test_csrf_bad_origin_rejected(librarian):
    token = csrf_from(librarian)
    r = librarian.post("/admin/deleteBook", data={"book_id": "1", "csrf_token": token},
                       headers={"Origin": "https://evil.example"})
    assert r.status_code == 400


def test_open_redirect_blocked(client):
    token = csrf_from(client)
    r = client.post("/login?next=https://evil.example/phish",
                    data={"username": "student1", "password": STU_PW, "csrf_token": token})
    assert r.status_code == 302 and "evil.example" not in r.headers["Location"]


def test_cookie_flags(client):
    csrf_from(client)
    r = client.get("/login")
    cookie = next((c for c in r.headers.getlist("Set-Cookie") if c.startswith("library_session")), "")
    login_resp = login(client, "student1", STU_PW)
    cookie = next(c for c in login_resp.headers.getlist("Set-Cookie") if c.startswith("library_session"))
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie
