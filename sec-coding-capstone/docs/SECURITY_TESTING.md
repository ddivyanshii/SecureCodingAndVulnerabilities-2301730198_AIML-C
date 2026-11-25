# Security Testing Guide

This guide covers how to reproduce every security test for the viva: automated tests, SAST, DAST and manual attacks.

Start the app first, in its own terminal:

```powershell
python run.py
```

Demo accounts come from `flask --app library_app seed-demo --password "Demo#2026pass"`.

---

## 1. Automated tests (pytest)

```powershell
python -m pytest -v
```

The expected result is **129 passed**. To run one area only:

```powershell
python -m pytest tests/test_authorization.py -v
```

## 2. Live attack demo

```powershell
python scripts/security_demo.py
```

This runs 16 real attacks against a throw-away database and prints `[BLOCKED]` or `[VULNERABLE]` for each one. It ends with `All 16 attacks blocked.`

## 3. Bandit (Python SAST)

```powershell
bandit -r library_app -c pyproject.toml
```

The expected result is `No issues identified.` To feed the results into SonarQube:

```powershell
New-Item -ItemType Directory -Force reports; bandit -r library_app -c pyproject.toml -f json -o reports/bandit.json
```

## 4. Dependency CVE scan

```powershell
pip-audit -r requirements.txt
```

## 5. SonarQube (static analysis)

1. Start SonarQube locally:
   ```powershell
   docker run -d --name sonarqube -p 9000:9000 sonarqube:community
   ```
2. Open http://localhost:9000 and log in with `admin`/`admin`. You will be asked to change the password. Then go to **My Account → Security → Generate Token**.
3. Install the scanner from https://docs.sonarsource.com/sonarqube/latest/analyzing-source-code/scanners/sonarscanner/ and run it from the project root. `sonar-project.properties` is already configured.
   ```powershell
   sonar-scanner "-Dsonar.host.url=http://localhost:9000" "-Dsonar.token=<YOUR_TOKEN>"
   ```
4. In the dashboard, show these sections: **Security Hotspots**, **Vulnerabilities**, **Bugs**, **Code Smells** and **Duplications**.
   - A likely hotspot is the use of `hashlib`. Review it as *Safe*, because it is scrypt for passwords and SHA-256 for session-token lookup, not plain password hashing.
   - Another likely hotspot is the Flask `SECRET_KEY` configuration. Review it as *Safe*, because the key comes from an environment variable and is never hard-coded.

## 6. OWASP ZAP (dynamic analysis)

### 6a. Baseline (passive) scan with no login

```powershell
docker run --rm -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://host.docker.internal:5000 -r zap-baseline.html
```

You can also use the ZAP desktop app: **Automated Scan → URL `http://127.0.0.1:5000` → Attack**.

The scan should find no missing CSP, X-Frame-Options or X-Content-Type-Options headers, and no cookie without HttpOnly or SameSite.

Expected informational alerts that you should explain in the viva:
- *Cookie without Secure flag.* The dev server runs on plain HTTP. Setting `LIBRARY_SECURE_COOKIES=1` behind HTTPS fixes this.
- *Strict-Transport-Security header not set.* HSTS is only sent over HTTPS, by design.

### 6b. Authenticated active scan (desktop ZAP)

1. Open the app through ZAP's proxy browser (**Quick Start → Manual Explore**) and log in as `librarian1`.
2. Click through every page: Books, Add book, Issue, Loans and Activity.
3. Right-click the site → **Attack → Active Scan**.
4. Every POST needs a `csrf_token`. ZAP detects tokens named `csrf_token` automatically; check this under **Options → Anti-CSRF Tokens** and add `csrf_token` if it is missing.
5. Expected result: no SQL-injection or XSS alerts. 400 responses are normal, because the validators reject ZAP's payloads.

## 7. Burp Suite: the key manual demonstrations

Set the browser proxy to Burp (127.0.0.1:8080) and keep **Intercept** on.

| # | Test | Steps | Expected |
|---|---|---|---|
| 1 | Inspect login | Log in and look at the POST `/login` | The body has `username`, `password` and `csrf_token` (no role). The response sets `library_session` with `HttpOnly; SameSite=Lax`. |
| 2 | **Forced browsing** | Log in as the librarian, click **Remove** and send the request to **Repeater**. Log out, log in as `student1`, copy the student's cookie and `csrf_token` into the Repeater request, then send it. | **403 Forbidden**, the book still exists, and `AUTHZ_DENIED` appears in the librarian's Activity log. |
| 3 | Typed URL | As a student, open `http://127.0.0.1:5000/admin/deleteBook` | **405 Method Not Allowed**, because GET never changes data |
| 4 | Mass assignment | In POST `/register`, add `&role=librarian` | The account is created as **student** |
| 5 | Hidden-field tampering | Change `book_id=1` to `book_id=1 OR 1=1` or `-1` | Flash message "Enter a whole number…", nothing deleted |
| 6 | CSRF | Delete `csrf_token` from any POST | **400 Bad Request**, `CSRF_INVALID` logged |
| 7 | Cookie replay | Copy the cookie, log out, then replay the old cookie on `/my-books` | Redirect to `/login` |
| 8 | Brute force | Use Intruder on `/login` with 6 wrong passwords | After 5 attempts the account is locked. After 10 from one IP the response is **429**. |

## 8. Manual payload checklist (no tools needed)

| Where | Input | Expected |
|---|---|---|
| Login username | `' OR '1'='1` | "Invalid username or password." |
| Login username | `admin'--` | Same generic message |
| Search | `x' OR '1'='1` | Rejected by validation: "Search may contain letters, digits…" (`=` is not allowed) |
| Search | `Python' --` | Passes validation (apostrophes are allowed), 0 results, no SQL error |
| Search | `<script>alert(1)</script>` | Shown as text, no alert box |
| Search field (URL) | `/books/search?q=a&field=password_hash` | 400 "Invalid search field." |
| Add book → Book name | `Food'; DROP TABLE books; --` | Rejected by validation, table intact |
| Add book → Quantity | `-500`, `0`, `1001`, `5abc`, `1e3`, `999999999999999999` (remove `maxlength` in DevTools first for long values) | "Enter a whole number between 1 and 1000." |
| Add book → Category | Edit the `<select>` in DevTools to `Hacking` | "Choose a category from the list." |
| Register → Name | `R2D2` | "Only letters and single spaces are allowed." |
| Register → Roll no. | `123` | "Must be at least 10 characters." |
| Issue → 4th book to the same student | | "Student already has 3 books (limit 3)." |
| Any URL | `/does-not-exist` | Generic 404 page, no stack trace |
| Idle 15 min, then click | | "Your session expired due to inactivity." |

To demo the timeout quickly, set `LIBRARY_IDLE_TIMEOUT=60` in `.env` and restart.

## 9. Where to see the evidence

- **In the UI:** Librarian → **Activity log** (`/admin/activity`)
- **Files:** `logs/security.log` (one line per event) and `logs/app.log` (stack traces for incident ids)
