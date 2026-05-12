PRAGMA foreign_keys = ON;

-- ── Users ─────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
	user_id     INTEGER PRIMARY KEY,
	username    TEXT,
	first_name  TEXT,
	is_banned   INTEGER NOT NULL DEFAULT 0,
	created_at  TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
	last_active TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_active ON users(last_active);

-- ── TOTP Secrets ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS totp_secrets (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id    INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
	service    TEXT    NOT NULL,
	secret     TEXT    NOT NULL,
	created_at TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
	UNIQUE(user_id, service)
);

CREATE INDEX IF NOT EXISTS idx_totp_user_id ON totp_secrets(user_id);

-- ── Rate Limits ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS rate_limits (
	user_id      INTEGER PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
	count        INTEGER NOT NULL DEFAULT 1,
	window_start INTEGER NOT NULL  -- Unix milliseconds
);

-- ── Bot Event Log (Telemetry & Analytics) ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS event_log (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id    INTEGER NOT NULL,
	action     TEXT    NOT NULL,          -- 'cmd_start', 'add_service', 'get_code', 'del_service', etc.
	service    TEXT,                      -- Optional context
	created_at TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_event_log_user ON event_log(user_id);
CREATE INDEX IF NOT EXISTS idx_event_log_action ON event_log(action);
CREATE INDEX IF NOT EXISTS idx_event_log_time ON event_log(created_at);
