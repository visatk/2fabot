CREATE TABLE IF NOT EXISTS totp_secrets (
    user_id INTEGER NOT NULL,
    service TEXT NOT NULL,
    secret TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, service)
);
