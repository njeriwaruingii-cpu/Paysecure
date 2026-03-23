-- PaySecure Database Schema
-- Engine: SQLite

-- ─────────────────────────────────────────
-- USERS
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    email         TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'student',  -- 'student' | 'admin'
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ─────────────────────────────────────────
-- ACTIVITY LOGS  (admin monitoring)
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS activity_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    action      TEXT    NOT NULL,   -- e.g. 'login', 'verify', 'learn_view'
    detail      TEXT,               -- extra context (page visited, verdict, etc.)
    ip_address  TEXT,
    logged_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- ─────────────────────────────────────────
-- VERIFICATION HISTORY
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS verifications (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    input_text  TEXT    NOT NULL,   -- the message/link pasted by user
    verdict     TEXT    NOT NULL,   -- 'safe' | 'suspicious' | 'dangerous'
    flags       TEXT,               -- JSON list of triggered warning flags
    checked_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- ─────────────────────────────────────────
-- SEED: default admin account
-- password = admin123  (hashed at app startup, not here)
-- ─────────────────────────────────────────
-- Admin is inserted programmatically in app.py to allow proper hashing.

-- ─────────────────────────────────────────
-- PHISHING RULES (from School ERD)
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS phishing_rules (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern TEXT    NOT NULL,
    type    TEXT    NOT NULL, -- 'keyword', 'suspicious_domain', 'safe_domain'
    weight  INTEGER DEFAULT 1
);