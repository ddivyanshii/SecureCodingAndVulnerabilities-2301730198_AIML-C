from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from library_app import create_app
from library_app.db import get_db
from library_app.services import auth_service, book_service

GREEN, RED, BOLD, END = "\033[92m", "\033[91m", "\033[1m", "\033[0m"
results: list[bool] = []


def check(title: str, blocked: bool, detail: str) -> None:
    results.append(blocked)
    tag = f"{GREEN}BLOCKED{END}" if blocked else f"{RED}VULNERABLE{END}"
    print(f"  [{tag}] {title}\n            {detail}")


def csrf(client) -> str:
    for url in ("/login", "/books/search"):
        m = re.search(r'name="csrf_token" value="([^"]+)"', client.get(url).get_data(as_text=True))
        if m:
            return m.group(1)
    return ""


def login(client, user: str, pw: str):
    return client.post("/login", data={"username": user, "password": pw, "csrf_token": csrf(client)})


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="library-demo-"))
    app = create_app({"DATABASE": str(tmp / "demo.db"), "LOG_DIR": str(tmp / "logs"),
                      "SECRET_KEY": "demo-only-" + "k" * 40})
    with app.app_context():
        auth_service.create_librarian(username="librarian1", full_name="Asha Librarian",
                                      email="lib@college.example", password="Librarian#2026")
        auth_service.register_student(username="student1", full_name="Ravi Kumar", email="s1@college.example",
                                      roll_number="2023CSE001", password="Student#2026")
        book_service.add_book(book_code="CS101", title="Python Basics", author="Guido Rossum",
                              category="Computer Science", quantity=5)

    def count(sql: str) -> int:
        with app.app_context():
            return get_db().execute(sql).fetchone()[0]

    print(f"\n{BOLD}Secure College Library - live attack demonstration{END}\n")

    print(f"{BOLD}1. SQL injection{END}")
    c = app.test_client()
    r = c.post("/login", data={"username": "' OR '1'='1", "password": "' OR '1'='1", "csrf_token": csrf(c)})
    check("Login bypass with ' OR '1'='1", r.status_code == 401, f"HTTP {r.status_code}, generic error shown")
    login(c, "student1", "Student#2026")
    r = c.get("/books/search", query_string={"q": "x' OR '1'='1", "field": "title"})
    check("Search dump with x' OR '1'='1", "Python Basics" not in r.get_data(as_text=True),
          "payload treated as literal text by parameterised query")
    r = c.get("/books/search", query_string={"q": "x", "field": "title FROM users--"})
    check("Inject column name via 'field' parameter", r.status_code == 400, "allow-list rejected it")

    print(f"\n{BOLD}2. Broken access control (forced browsing){END}")
    r = c.post("/admin/deleteBook", data={"book_id": "1", "csrf_token": csrf(c)})
    check("Student POSTs /admin/deleteBook", r.status_code == 403 and count("SELECT COUNT(*) FROM books") == 1,
          f"HTTP {r.status_code}; book still exists; AUTHZ_DENIED logged")
    r = c.get("/admin/activity")
    check("Student opens /admin/activity", r.status_code == 403, f"HTTP {r.status_code}")
    anon = app.test_client()
    r = anon.get("/admin/books")
    check("Anonymous opens /admin/books", r.status_code == 302, "redirected to /login")

    print(f"\n{BOLD}3. Cross-site request forgery{END}")
    lib = app.test_client()
    login(lib, "librarian1", "Librarian#2026")
    r = lib.post("/admin/deleteBook", data={"book_id": "1"})
    check("Forged POST without CSRF token (librarian's browser)", r.status_code == 400, f"HTTP {r.status_code}")

    print(f"\n{BOLD}4. Input validation / integer security{END}")
    for qty in ["-500", "999999999999999999", "5abc", "1e3"]:
        r = lib.post("/admin/addBook", data={"book_code": "CS900", "title": "Test", "author": "Tester",
                                             "category": "General", "quantity": qty, "csrf_token": csrf(lib)})
        check(f"Add book with quantity={qty}", r.status_code == 400, "rejected: whole number 1-1000 only")
    r = lib.post("/admin/addBook", data={"book_code": "CS900", "title": "Test", "author": "Tester",
                                         "category": "Hacking", "quantity": "1", "csrf_token": csrf(lib)})
    check("Category outside whitelist", r.status_code == 400, "rejected by allow-list")

    print(f"\n{BOLD}5. Cross-site scripting{END}")
    r = c.get("/books/search", query_string={"q": "<script>alert(1)</script>"})
    check("Reflected <script> in search", "<script>alert(1)</script>" not in r.get_data(as_text=True),
          "auto-escaped to &lt;script&gt; + CSP blocks inline scripts")

    print(f"\n{BOLD}6. Brute force{END}")
    b = app.test_client()
    for _ in range(5):
        login(b, "student1", "wrong-guess1")
    r = login(b, "student1", "Student#2026")
    check("Correct password after 5 failures", r.status_code == 401, "account locked for 15 minutes")

    print(f"\n{BOLD}7. Session security{END}")
    with c.session_transaction() as sess:
        stolen = dict(sess)
    c.post("/logout", data={"csrf_token": csrf(c)})
    with c.session_transaction() as sess:
        sess.update(stolen)
    r = c.get("/my-books")
    check("Replay cookie after logout", r.status_code == 302, "server-side session was deleted")

    print(f"\n{BOLD}8. Error handling{END}")
    r = anon.get("/no/such/page")
    check("Unknown URL", r.status_code == 404 and "Traceback" not in r.get_data(as_text=True),
          "generic 404 page, no stack trace")

    denied = count("SELECT COUNT(*) FROM audit_log WHERE outcome != 'SUCCESS'")
    print(f"\n{BOLD}Audit log recorded {denied} failed/denied events.{END}")
    ok = all(results)
    print(f"{BOLD}{'All' if ok else 'NOT all'} {len(results)} attacks blocked.{END}\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
