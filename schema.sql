-- schema.sql
DROP TABLE IF EXISTS totp_secrets;
DROP TABLE IF EXISTS users;

-- User Profile Table
CREATE TABLE users (
    user_id INTEGER PRIMARY KEY,
    username TEXT,
    first_name TEXT,
    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2FA Secrets Table
CREATE TABLE totp_secrets (
    user_id INTEGER NOT NULL,
    service TEXT NOT NULL,
    secret TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, service),
    FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE
);
