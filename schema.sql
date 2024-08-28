DROP TABLE IF EXISTS user;
DROP TABLE IF EXISTS users;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT NOT NULL,
    is_admin BOOLEAN NOT NULL DEFAULT 0  -- Dodanie kolumny is_admin
);

CREATE TABLE IF NOT EXISTS archive (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    bot_id INTEGER NOT NULL,
    group_name TEXT NOT NULL,
    total_calls INTEGER,
    successful_calls INTEGER,
    failed_calls INTEGER,
    voicemail_calls INTEGER,
    cancelled_calls INTEGER,
    bye_status_calls INTEGER,
    other_errors INTEGER,
    average_call_duration REAL,
    date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
);