PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    username         TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    full_name        TEXT    NOT NULL,
    email            TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    roll_number      TEXT    UNIQUE,
    password_hash    TEXT    NOT NULL,
    role             TEXT    NOT NULL CHECK (role IN ('student', 'librarian')),
    is_active        INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    failed_attempts  INTEGER NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
    locked_until     REAL,
    created_at       TEXT    NOT NULL DEFAULT (datetime('now')),
    CHECK (role = 'librarian' OR roll_number IS NOT NULL)
);

CREATE TABLE IF NOT EXISTS books (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    book_code   TEXT    NOT NULL UNIQUE,
    title       TEXT    NOT NULL,
    author      TEXT    NOT NULL,
    category    TEXT    NOT NULL CHECK (category IN (
                    'Computer Science', 'Electronics', 'Mathematics', 'Physics',
                    'Mechanical', 'Civil', 'Management', 'General')),
    quantity    INTEGER NOT NULL CHECK (quantity BETWEEN 1 AND 1000),
    available   INTEGER NOT NULL CHECK (available >= 0 AND available <= quantity),
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS loans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    book_id      INTEGER NOT NULL REFERENCES books(id) ON DELETE RESTRICT,
    student_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    issued_by    INTEGER NOT NULL REFERENCES users(id),
    issued_at    TEXT    NOT NULL,
    due_at       TEXT    NOT NULL,
    returned_at  TEXT,
    returned_to  INTEGER REFERENCES users(id)
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_active_loan
    ON loans (book_id, student_id) WHERE returned_at IS NULL;

CREATE TABLE IF NOT EXISTS sessions (
    token_hash  TEXT    PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  REAL    NOT NULL,
    last_seen   REAL    NOT NULL,
    ip          TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    event     TEXT    NOT NULL,
    outcome   TEXT    NOT NULL CHECK (outcome IN ('SUCCESS', 'FAILURE', 'DENIED')),
    user_id   INTEGER,
    username  TEXT,
    ip        TEXT,
    details   TEXT
);

CREATE INDEX IF NOT EXISTS ix_loans_student ON loans (student_id, returned_at);
CREATE INDEX IF NOT EXISTS ix_audit_ts ON audit_log (ts);
