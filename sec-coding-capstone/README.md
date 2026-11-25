# Secure College Library Management System

**ENSP 351: Secure Coding and Vulnerabilities, Capstone Project 7**
Python 3.10+ · Flask 3.1 · SQLite · no JavaScript

A small library system for a college with two roles, **Student** and **Librarian**. Security was designed into every layer, following the Secure SDLC taught in the course. All ten mandatory security requirements from the project brief are implemented. The test suite has **129 automated tests**, Bandit reports **0 issues**, and the live attack demo blocks **16 of 16 attacks**.

| Role | Can do |
|---|---|
| **Student** | Register, log in, search books, view their own issued books, log out |
| **Librarian** | Log in, add books, add copies, remove books, issue books, return books, view active loans, view the activity (audit) log |

> The scenario from the project brief: *"A normal user should not be allowed to call `/admin/deleteBook` even if they manually enter the URL."* The app returns **403 Forbidden**, leaves the book in place and writes an `AUTHZ_DENIED` entry to the audit log. See [`tests/test_authorization.py`](tests/test_authorization.py).

---

## Table of contents

1. [Quick start](#1-quick-start)
2. [Project structure](#2-project-structure)
3. [How it works: the request pipeline](#3-how-it-works-the-request-pipeline)
4. [The 10 mandatory security requirements](#4-the-10-mandatory-security-requirements)
5. [Module-by-module explanation](#5-module-by-module-explanation)
6. [Database design](#6-database-design)
7. [Threat model (STRIDE)](#7-threat-model-stride)
8. [Security testing](#8-security-testing)
9. [Mapping to the syllabus](#9-mapping-to-the-syllabus)
10. [Known limitations and future work](#10-known-limitations-and-future-work)

---

## 1. Quick start

Run these commands in PowerShell from the project folder.

```powershell
python -m venv .venv
```
```powershell
.venv\Scripts\Activate.ps1
```
```powershell
pip install -r requirements-dev.txt
```

Create your local secrets file. It is git-ignored, so the secrets are never committed.

```powershell
Copy-Item .env.example .env
```
```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```
Paste the printed value into `.env` as `LIBRARY_SECRET_KEY=...`.

Load the demo data: 1 librarian, 2 students and 8 books. If you leave out `--password`, a random password is generated and printed **once**.

```powershell
flask --app library_app seed-demo --password "Demo#2026pass"
```

Run the app:

```powershell
python run.py
```

Open http://127.0.0.1:5000 and log in as `librarian1`, `student1` or `student2`.

Other useful commands:

| Command | Purpose |
|---|---|
| `flask --app library_app create-librarian` | Create a real librarian account. This CLI is the **only** way to get the librarian role. |
| `flask --app library_app init-db` | Create the tables (safe to run more than once) |
| `flask --app library_app purge-sessions` | Delete expired server-side sessions |
| `python -m pytest` | Run all 129 tests |
| `python scripts/security_demo.py` | Live attack demo: prints BLOCKED or VULNERABLE for 16 attacks |
| `bandit -r library_app -c pyproject.toml` | Static security analysis (SAST) |
| `pip-audit -r requirements.txt` | Check dependencies for known CVEs |

---

## 2. Project structure

```
sec-coding-capstone/
├── run.py                      # Dev entry point: binds 127.0.0.1, debug always OFF
├── requirements.txt            # Runtime dependencies (Flask, python-dotenv)
├── requirements-dev.txt        # + pytest, bandit, pip-audit
├── pyproject.toml              # pytest + bandit config
├── sonar-project.properties    # SonarQube scanner config
├── .env.example                # Template for secrets (the real .env is git-ignored)
├── .gitignore
│
├── library_app/                # ── the application package ──
│   ├── __init__.py             # App factory: wires the security pipeline, error handlers, CLI
│   ├── config.py               # Settings from env vars; cookie flags; timeouts; fail-closed on weak key
│   ├── db.py                   # SQLite connection, parameterised queries, BEGIN IMMEDIATE transactions
│   ├── schema.sql              # Tables + CHECK/UNIQUE/FK constraints (DB-level defence in depth)
│   ├── seed.py                 # Demo data (random passwords unless one is supplied)
│   │
│   ├── security/               # ── reusable security building blocks ──
│   │   ├── validators.py       # Regex + whitelist + numeric-range validation
│   │   ├── passwords.py        # scrypt hashing, per-user salt, constant-time verify
│   │   ├── sessions.py         # Server-side sessions, idle/absolute timeout, fixation defence
│   │   ├── authz.py            # Role-based access control: the reference monitor (complete mediation)
│   │   ├── csrf.py             # CSRF token + Origin check on every POST
│   │   ├── rate_limit.py       # Per-IP sliding-window login throttle
│   │   ├── audit.py            # Activity log (DB + rotating files), log-injection safe
│   │   └── headers.py          # CSP, X-Frame-Options, nosniff, no-store, HSTS
│   │
│   ├── services/               # ── business logic (no HTTP here) ──
│   │   ├── __init__.py         # ServiceError: messages that are safe to show users
│   │   ├── auth_service.py     # register / authenticate / lockout / timing equalisation
│   │   ├── book_service.py     # search / add / add copies / delete
│   │   └── loan_service.py     # issue / return / my loans / dashboard stats / activity
│   │
│   ├── routes/                 # ── thin HTTP controllers (Flask blueprints) ──
│   │   ├── auth.py             # /, /register, /login, /logout
│   │   ├── student.py          # /dashboard, /books/search, /my-books
│   │   └── librarian.py        # /admin/*  (addBook, deleteBook, issueBook, returnBook, ...)
│   │
│   ├── templates/              # Jinja2 HTML (auto-escaped); no inline JS or CSS
│   └── static/style.css
│
├── tests/                      # 129 pytest tests, one file per security area
│   ├── conftest.py             # Isolated temp DB per test + login/CSRF helpers
│   ├── test_validators.py      # 59 tests: regex, whitelist, integers, redirects
│   ├── test_passwords.py       # 4 tests: salting, verify, tampered hashes
│   ├── test_auth_and_sessions.py   # 16 tests: lockout, fixation, logout, timeouts, CSRF
│   ├── test_authorization.py   # 23 tests: RBAC, /admin/deleteBook, IDOR, deny-by-default
│   ├── test_injection_and_xss.py   # 7 tests: SQLi, LIKE wildcards, XSS, log injection
│   ├── test_library_features.py    # 14 tests: business rules + integer security
│   └── test_errors_and_headers.py  # 6 tests: generic errors, headers, body-size limit
│
├── scripts/security_demo.py    # Presentation script: runs 16 real attacks
└── docs/SECURITY_TESTING.md    # Step-by-step SonarQube, OWASP ZAP, Burp Suite and manual tests
```

**Layering rule:** *routes → services → db*. Routes only parse and validate the HTTP request and render templates. Services hold every business rule and can be unit-tested without HTTP. Only services and `db.py` touch SQL. This separation keeps each security decision in one reviewable place.

---

## 3. How it works: the request pipeline

Every request passes through the same pipeline, which is registered once in `library_app/__init__.py`. No view can skip it.

```
 Browser
   │  HTTPS (in production)   cookie: library_session = signed{ sid, csrf }
   ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│ 0. Werkzeug: MAX_CONTENT_LENGTH = 16 KB   → 413 if the body is too large         │
│ 1. sessions.load_current_user()                                                │
│      sid → SHA-256 → look up sessions table → idle > 15 min or age > 8 h?      │
│      → reload role + is_active FROM THE DATABASE → g.user                     │
│ 2. authz.enforce_access_policy()     ← REFERENCE MONITOR                       │
│      endpoint policy = public | authenticated | ("librarian",) | ("student",)  │
│      no policy declared → 403 (deny by default)                                │
│      not logged in → redirect /login ;  wrong role → 403 + AUTHZ_DENIED log    │
│ 3. csrf.verify_csrf()                                                          │
│      POST without a matching token, or a foreign Origin → 400 + CSRF log       │
│ 4. View function (routes/*)                                                    │
│      validators.* on EVERY field → services.* → parameterised SQL              │
│ 5. headers.apply_security_headers()                                            │
│      CSP, X-Frame-Options: DENY, nosniff, Referrer-Policy, no-store            │
└───────────────────────────────────────────────────────────────────────────────┘
   │  Any exception → generic error page + incident id; stack trace → logs/app.log
   ▼
 Response
```

### Example: what happens when a librarian removes a book

1. The librarian clicks **Remove** on `/admin/books`. This is a `<form method="post">` with hidden `csrf_token` and `book_id` fields. It is not a GET link, because GET must never change data.
2. `load_current_user` finds the session and confirms that the user is still an active librarian in the database.
3. `enforce_access_policy` checks the endpoint `librarian.delete_book`, whose policy is `("librarian",)`. The user is allowed through.
4. `verify_csrf` compares the posted token with the session token using `hmac.compare_digest`. They match.
5. The view validates `book_id` with `validate_record_id`, which accepts digits only, at most 9 digits, and a value ≥ 1.
6. `book_service.delete_book` opens a `BEGIN IMMEDIATE` transaction, checks that no copies are on loan and that the book has no loan history, then runs `DELETE FROM books WHERE id = ?`.
7. `log_event("BOOK_DELETE", "SUCCESS", "CS101 'Python Basics'")` writes a row to `audit_log` and a line to `logs/security.log`.

If a **student** sends the same request, step 3 stops it with a 403. Steps 4–7 never run.

---

## 4. The 10 mandatory security requirements

| # | Requirement (from brief) | Where / how it is implemented |
|---|---|---|
| 1 | **Validate all input** | `security/validators.py`. Every form field and query parameter is checked for type, length, format and range on the **server**. Hidden fields such as `book_id` and `loan_id` are validated too, because attackers control them. |
| 2 | **Use regex where appropriate** | Book ID `^[A-Z]{2,4}[0-9]{3,4}$`, roll number `^[A-Z0-9]{10,12}$`, name, email, username, title, author and search. All use `re.fullmatch` with `re.ASCII`, so a trailing `\n` or non-ASCII digits cannot slip through. |
| 3 | **Use whitelist validation** | `CATEGORIES` (8 fixed values), `SEARCH_FIELDS` (maps `title/author/code` to a trusted column name), `ROLES`. Anything not on a list is rejected. |
| 4 | **Hash passwords** | `security/passwords.py`: **scrypt** (n=2¹⁴, r=8, p=1), 16-byte random salt per user, `hmac.compare_digest`, safe parsing of stored parameters, transparent re-hash. |
| 5 | **Parameterised SQL** | Every query in `services/*` and `security/*` uses `?` placeholders. No f-string or `+` ever builds SQL from input. Searches escape LIKE wildcards. |
| 6 | **Authentication** | `services/auth_service.py` + `routes/auth.py`: generic error messages, dummy-hash timing equalisation, lockout after 5 failures (15 min), per-IP rate limit (10 per 5 min), password policy. |
| 7 | **Authorisation** | `security/authz.py`: every endpoint declares `@public`, `@login_required` or `@roles_required(...)`. A global reference monitor enforces it, undeclared endpoints are denied, and the role is re-read from the DB on every request. Self-registration can only create students. |
| 8 | **Secure session handling** | `security/sessions.py`: server-side sessions with random 256-bit tokens, stored as SHA-256 hashes. 15-min idle and 8-h absolute timeouts. New token on login (fixation defence). Logout deletes the server record. Cookies are `HttpOnly`, `SameSite=Lax` and `Secure` in production. CSRF tokens on every POST. |
| 9 | **Exception handling and logging** | `__init__.py` error handlers show users a generic message and an incident id. Full tracebacks go to `logs/app.log`. `security/audit.py` logs every login, failure, lockout, denial, CSRF failure and data change to the DB and to `logs/security.log`, with log-injection sanitising. |
| 10 | **Test with SonarQube and OWASP ZAP** | `sonar-project.properties` and the step-by-step guide in [`docs/SECURITY_TESTING.md`](docs/SECURITY_TESTING.md) (SonarQube, ZAP baseline and full scan, Burp Suite, manual payloads). Also included: Bandit (0 issues), pip-audit, 129 pytest tests and `scripts/security_demo.py`. |

### Additional controls (beyond the 10)

- **CSRF protection.** Token plus Origin check, and the token is rotated at login.
- **XSS defence.** Jinja2 auto-escaping is on and `|safe` is never used. A strict CSP (`script-src 'self'`, no inline code) means injected script would not run even if it got through.
- **Clickjacking.** `X-Frame-Options: DENY` and `frame-ancestors 'none'`.
- **Open redirect.** `?next=` only accepts same-site relative paths (`is_safe_redirect`).
- **IDOR.** `/my-books` takes the student id from the session and never from the URL.
- **Race conditions (TOCTOU).** Issue and return run inside `BEGIN IMMEDIATE` transactions.
- **Integer security.** Digit-only parsing, a digit-count cap before `int()`, range checks, a 1000-copy stock cap checked on the *result* of an addition, and DB `CHECK (available >= 0 AND available <= quantity)`.
- **Defence in depth in the DB.** CHECK constraints on role, category, quantity and available. UNIQUE partial index (one active loan per book per student). Foreign keys enforced.
- **DoS limits.** 16 KB request-body cap, 128-char password cap (keeps the hashing cost bounded), 50-char search cap, `LIMIT` on every listing query, and the rate limiter bounds its own memory.
- **Secrets management.** No secrets in code. `.env` is git-ignored. Production refuses to start without a ≥32-char key. Demo passwords are random unless you supply one.
- **No debug mode.** `debug=False` is hard-coded. The app binds to `127.0.0.1` only.
- **No-cache on authenticated pages.** On a shared lab PC, pressing Back after logout does not show the previous user's data.

---

## 5. Module-by-module explanation

### `config.py`: secure configuration
Reads every setting from environment variables. `_resolve_secret_key()` **fails closed**: in production it raises `RuntimeError` if `LIBRARY_SECRET_KEY` is missing or shorter than 32 chars. In development it generates a random key and logs a warning. Numeric env values are range-checked with `_env_int()`.

### `db.py`: data access
- `get_db()` opens one connection per request and enables `PRAGMA foreign_keys = ON`.
- `transaction()` is a context manager that runs `BEGIN IMMEDIATE … COMMIT/ROLLBACK`. Taking the write lock *before* reading removes check-then-act races.

### `security/validators.py`: input validation
Each `validate_*()` function **normalises** the value (strip, upper-case codes, collapse spaces), then checks **type → length → regex/whitelist → range**. It returns the clean value or raises `ValidationError(field, message)`. The message is safe to show the user.

`validate_bounded_int()` shows the integer-security approach:
```python
"-5"     → rejected  (no sign allowed)
"5.0"    → rejected  (no decimal point)
"1e3"    → rejected  (no exponent)
"٥"      → rejected  (Arabic-Indic digit, even though "٥".isdigit() is True)
"99999999999999999999" → rejected before int() (too many digits; would overflow SQLite INTEGER)
"1001"   → rejected  (range 1–1000)
```

### `security/passwords.py`: password storage
`hash_password()` produces `scrypt$16384$8$1$<salt>$<hash>`. `verify_password()` never raises. It rejects tampered parameters (for example `n = 2³⁰` would exhaust RAM) and compares in constant time. `DUMMY_HASH` is used for unknown usernames so the response time does not reveal which usernames exist.

### `security/sessions.py`: sessions
The browser holds only `sid` (random), inside Flask's HMAC-signed cookie. The DB stores `sha256(sid)`. On each request the module checks the timeouts, reloads the user and refreshes `last_seen`. `create_session()` clears the old session and issues a new `sid` and CSRF token. `destroy_session()` deletes the DB row, which is why a stolen cookie stops working after logout.

### `security/authz.py`: authorisation (complete mediation)
Decorators attach an access policy to each view. `enforce_access_policy()` runs before every request and is the reference monitor: **always invoked, small, verifiable, and deny-by-default**. The decorators also re-check inside the wrapper (defence in depth). The test `test_every_endpoint_declares_an_access_policy` makes sure no route is left unprotected.

### `security/csrf.py`
`get_csrf_token()` is exposed to templates. `verify_csrf()` runs on POST/PUT/PATCH/DELETE and returns 400 on a missing or wrong token or a foreign `Origin`.

### `security/audit.py`
`log_event(event, outcome, details)` writes to the `audit_log` table and to `logs/security.log`. `sanitize_for_log()` replaces CR/LF and control characters and truncates long values, which prevents log forging. `configure_logging()` sets up rotating files (1 MB × 5).

### `security/rate_limit.py`
Thread-safe sliding window per IP, with bounded memory. It complements per-account lockout: lockout stops many guesses against one user, and the rate limit stops one attacker trying many users.

### `security/headers.py`
Adds CSP, anti-framing, nosniff, Referrer-Policy and Permissions-Policy to every response. Authenticated pages also get `Cache-Control: no-store`. HSTS is added when served over HTTPS.

### `services/*`
These contain all business rules: max 3 books per student, 14-day loans, no duplicate active loan, no deleting books that are on loan, and the stock cap. They raise `ServiceError` with safe messages. Routes catch these and show them. Unexpected exceptions go to the generic 500 handler.

### `routes/*`
These are thin controllers following the pattern *collect fields → validate all of them → call the service → flash/redirect or re-render with errors*. All `/admin/*` routes use `@roles_required("librarian")`. All state changes are POST-only.

### `templates/`
Every variable is auto-escaped. There are no inline `<script>` or `style=""` attributes, so the CSP can stay strict. HTML `maxlength` and `pattern` hints are there for usability only; the server is the authority.

---

## 6. Database design

```
users(id, username UNIQUE, full_name, email UNIQUE, roll_number UNIQUE,
      password_hash, role CHECK IN('student','librarian'), is_active,
      failed_attempts, locked_until, created_at)

books(id, book_code UNIQUE, title, author,
      category CHECK IN(8 categories),
      quantity CHECK 1..1000,
      available CHECK 0..quantity)

loans(id, book_id → books, student_id → users, issued_by → users,
      issued_at, due_at, returned_at, returned_to → users)
      UNIQUE (book_id, student_id) WHERE returned_at IS NULL

sessions(token_hash PK, user_id → users ON DELETE CASCADE, created_at, last_seen, ip)

audit_log(id, ts, event, outcome CHECK IN('SUCCESS','FAILURE','DENIED'),
          user_id, username, ip, details)
```

The constraints are the **last line of defence**: even if a Python check were removed by mistake, the DB would still refuse negative stock or an unknown role (`test_database_constraints_are_last_line_of_defence`).

---

## 7. Threat model (STRIDE)

**Data-flow summary:** Browser (untrusted) ⇄ **[trust boundary 1: HTTP]** ⇄ Flask app ⇄ **[trust boundary 2: process ↔ file]** ⇄ SQLite DB + log files.

| STRIDE | Threat in this app | Control(s) | Response |
|---|---|---|---|
| **S**poofing | Password guessing, credential stuffing, stolen session cookie | scrypt, lockout, IP rate limit, HttpOnly/SameSite/Secure cookies, server-side sessions, timeouts | Mitigate |
| **T**ampering | SQL injection, editing hidden `book_id`, forged POST (CSRF), editing the cookie | Parameterised SQL, validators, CSRF token, HMAC-signed cookie, DB constraints | Mitigate |
| **R**epudiation | Librarian denies deleting a book | `audit_log` with user, IP, time and details for every change | Mitigate |
| **I**nformation disclosure | Stack traces, user enumeration, another student's loans (IDOR), XSS stealing data | Generic errors with incident id, generic login message, timing equalisation, session-based ids, auto-escape and CSP | Mitigate |
| **D**enial of service | Huge bodies, huge numbers, password-hash flooding, LIKE `%` scans | 16 KB body cap, digit caps, 128-char password cap, rate limit, `LIMIT` on queries | Mitigate (+ Transfer to a reverse proxy in production) |
| **E**levation of privilege | Student calls `/admin/deleteBook`, registers with `role=librarian` | Reference monitor + deny-by-default, role re-read every request, role never taken from input | Mitigate |

**DREAD ranking of the top risks before controls** (1–10 per factor, average):

| Threat | D | R | E | A | D | Score | Priority |
|---|---|---|---|---|---|---|---|
| SQL injection on login | 10 | 10 | 8 | 10 | 9 | **9.4** | Critical |
| Forced browsing to `/admin/deleteBook` | 8 | 10 | 10 | 8 | 9 | **9.0** | Critical |
| Password brute force | 8 | 8 | 7 | 6 | 8 | **7.4** | High |
| CSRF on deleteBook | 8 | 7 | 6 | 8 | 5 | **6.8** | High |
| Stack-trace disclosure | 4 | 9 | 9 | 3 | 8 | **6.6** | Medium |

---

## 8. Security testing

| Tool / method | What it covers | Result |
|---|---|---|
| **pytest** (129 tests) | All controls above, including attack payloads | 129 passed |
| **`scripts/security_demo.py`** | 16 live attacks: SQLi, forced browsing, CSRF, integer abuse, XSS, brute force, cookie replay, error leakage | 16 of 16 blocked |
| **Bandit** (SAST) | Python security anti-patterns | 0 issues (1,239 LOC scanned) |
| **pip-audit** | Known CVEs in dependencies | Run before submission |
| **SonarQube** | Code smells, bugs, security hotspots | Steps in `docs/SECURITY_TESTING.md` |
| **OWASP ZAP** | Baseline and authenticated active scan | Steps in `docs/SECURITY_TESTING.md` |
| **Burp Suite** | Intercept and replay `/login`, `/admin/deleteBook` | Steps in `docs/SECURITY_TESTING.md` |

### Traceability matrix (Threat → Requirement → Test)

| Threat | Security requirement | Test(s) |
|---|---|---|
| SQLi `' OR '1'='1` | Parameterised SQL | `test_login_sqli_bypass_fails`, `test_search_injection_is_treated_as_data` |
| `Food'; DROP TABLE …` | Parameterised SQL + validation | `test_drop_table_in_add_book_rejected` |
| Student → `/admin/deleteBook` | RBAC / complete mediation | `test_student_cannot_delete_book_by_typing_url` |
| Missing decorator | Fail-safe default | `test_endpoint_without_policy_is_denied` |
| Mass assignment `role=librarian` | Role never from input | `test_register_creates_student_even_if_role_is_injected` |
| Quantity `-5` / `999999999999999999` | Numeric validation | `test_quantity_invalid`, `test_add_book_rejects_bad_quantity_and_category` |
| Brute force | Lockout + rate limit | `test_account_lockout_after_five_failures`, `test_ip_rate_limit` |
| Session fixation / replay | Secure sessions | `test_session_fixation_token_rotates_on_login`, `test_logout_revokes_server_side_session` |
| Idle session on lab PC | Session timeout | `test_idle_timeout`, `test_absolute_timeout` |
| CSRF | Token + Origin | `test_csrf_missing_or_wrong_token_rejected`, `test_csrf_bad_origin_rejected` |
| XSS | Auto-escape + CSP | `test_reflected_xss_is_escaped`, `test_security_headers_present` |
| Info leakage | Generic errors | `test_500_hides_internal_details`, `test_500_details_are_logged` |
| IDOR | Session-derived id | `test_no_idor_on_my_books` |
| Log forging | Log sanitising | `test_log_injection_neutralised` |

---

## 9. Mapping to the syllabus

| Unit topic | Where it shows up in this project |
|---|---|
| CIA triad | Confidentiality (hashing, RBAC, IDOR), Integrity (parameterised SQL, CSRF, DB constraints, signed cookie), Availability (rate limit, body cap, bounded inputs) |
| Authentication vs authorisation | `auth_service.authenticate()` checks who you are; `authz.enforce_access_policy()` checks what you are allowed to do |
| Coding standards / dirty code | No hard-coded secrets, no magic numbers (named constants in `config.py`), every return value checked, no debug endpoints, no dead code |
| Integer security | `validate_bounded_int`, stock-cap check on the *result* of the addition, DB CHECK constraints, digit-count cap before `int()` |
| SSDLC | Requirements (Section 4) → Design (threat model, Section 7) → Development (secure coding) → Testing (Section 8) → Deployment notes (Section 10) |
| Security requirements / traceability | Section 8 traceability matrix |
| Threat modelling: DFD, trust boundaries, STRIDE, DREAD | Section 7 |
| Secure architecture: attack-surface reduction, least privilege, defence in depth, isolation | Only 17 routes and no JS; students get the minimum rights; layered checks (validator → service → DB constraint); localhost binding |
| Saltzer & Schroeder: complete mediation, fail-safe defaults, economy of mechanism, open design, psychological acceptability | `authz.py` reference monitor; deny-by-default; one small pipeline; standard algorithms (scrypt) and no secret designs; clear error messages |
| Development phase: input validation, SQLi, secrets, tooling | `validators.py`, `db.py`, `.env`, Bandit, pytest, SonarQube |
| Test phase: boundary, negative, fuzz-style testing | Parametrised tests with boundary values (0, 1, 1000, 1001) and malicious payloads |

---

## 10. Known limitations and future work

- **Rate limiter is in-memory.** It resets on restart and is per-process. Production would use Redis or the reverse proxy's limiter.
- **No HTTPS in the dev server.** Deploy behind nginx or Caddy with TLS and set `LIBRARY_SECURE_COOKIES=1` (this enables Secure cookies and HSTS).
- **No MFA, no password reset, no e-mail verification.** These are natural next steps (TOTP via `pyotp`).
- **SQLite** is fine for one college library. A larger deployment would use PostgreSQL with a least-privilege DB user (no `DROP` rights for the app).
- **Production server:** use `waitress-serve --host 127.0.0.1 --port 8000 --call library_app:create_app` instead of `run.py`.
