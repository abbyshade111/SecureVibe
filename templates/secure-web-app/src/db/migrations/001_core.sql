-- Core tables for accounts, sessions, security events and settings.
-- Migrations are additive. Generated features add their own files numbered 100 and up.

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  name TEXT,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled', 'deleted')),
  must_change_password INTEGER NOT NULL DEFAULT 0,
  bootstrap_expires_at TEXT,
  failed_logins INTEGER NOT NULL DEFAULT 0,
  lock_until TEXT,
  last_login_at TEXT,
  -- One-time code (TOTP) enrolment. The seed is stored encrypted (field encryption, AAD users.totp_secret_enc.<id>).
  -- totp_used_steps holds the last few 30-second steps that were accepted so a code can never be replayed.
  totp_secret_enc TEXT,
  totp_confirmed INTEGER NOT NULL DEFAULT 0,
  totp_used_steps TEXT NOT NULL DEFAULT '[]',
  totp_created_at TEXT,
  totp_confirmed_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  deleted_at TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
  id_hash TEXT PRIMARY KEY,
  user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  ip TEXT,
  ua_hash TEXT,
  mfa_verified INTEGER NOT NULL DEFAULT 0,
  reauth_at TEXT,
  revoked_at TEXT,
  data TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id, created_at);
CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expires_at);

-- Append-only, hash-chained security event log. hash = sha256(prev_hash + canonical row).
CREATE TABLE IF NOT EXISTS audit_log (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  event TEXT NOT NULL,
  req_id TEXT,
  user_id TEXT,
  ip TEXT,
  route TEXT,
  outcome TEXT NOT NULL,
  fields TEXT NOT NULL DEFAULT '{}',
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_log_ts_idx ON audit_log(ts);
CREATE INDEX IF NOT EXISTS audit_log_event_idx ON audit_log(event, ts);
CREATE INDEX IF NOT EXISTS audit_log_user_idx ON audit_log(user_id, ts);

-- Password reset and invitation tokens: only the HMAC of the token is stored.
CREATE TABLE IF NOT EXISTS password_resets (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL DEFAULT 'reset' CHECK (kind IN ('reset', 'invite')),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT
);

-- Recovery codes for one-time code sign-in: only the keyed hash is stored, each code works once.
CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  used_at TEXT
);
CREATE INDEX IF NOT EXISTS mfa_recovery_user_idx ON mfa_recovery_codes(user_id);

-- API keys for the optional public API feature (sk_<prefix>_<secret>; only the HMAC is stored).
CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  prefix TEXT NOT NULL UNIQUE,
  hash TEXT NOT NULL UNIQUE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT,
  scopes TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL,
  last_used_at TEXT,
  revoked_at TEXT
);

-- Runtime settings an administrator may change (for example the AI kill switch).
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT
);

-- Stored responses for JSON API mutations sent with an Idempotency-Key header.
CREATE TABLE IF NOT EXISTS idempotency_keys (
  key_hash TEXT PRIMARY KEY,
  user_id TEXT,
  route TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  status INTEGER NOT NULL,
  body TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idempotency_created_idx ON idempotency_keys(created_at);
