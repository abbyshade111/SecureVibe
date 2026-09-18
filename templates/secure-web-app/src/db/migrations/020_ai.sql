-- Tables for the AI assistant (src/features/ai). They are always created so the administration pages and the
-- audit queries work even while the assistant is switched off; nothing is written unless the feature is on.

-- One row per model call made on behalf of a person: what was asked of the model (as hashes only — never the
-- text), what it cost and what the guard-rails decided.
CREATE TABLE IF NOT EXISTS ai_interactions (
  id TEXT PRIMARY KEY,
  user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  session_hash TEXT,
  model TEXT NOT NULL,
  provider TEXT NOT NULL,
  operation TEXT NOT NULL,
  endpoint TEXT NOT NULL DEFAULT '',
  input_tokens INTEGER NOT NULL DEFAULT 0,
  output_tokens INTEGER NOT NULL DEFAULT 0,
  prompt_hash TEXT NOT NULL,
  response_hash TEXT NOT NULL,
  injection_flagged INTEGER NOT NULL DEFAULT 0,
  filter_decision TEXT NOT NULL DEFAULT 'allowed',
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ai_interactions_user_idx ON ai_interactions(user_id, created_at);

-- Token counters per person, per session and per endpoint and day. The daily budget is read from here.
CREATE TABLE IF NOT EXISTS ai_usage (
  id TEXT PRIMARY KEY,
  user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
  session_hash TEXT NOT NULL DEFAULT '',
  endpoint TEXT NOT NULL DEFAULT '',
  day TEXT NOT NULL,
  requests INTEGER NOT NULL DEFAULT 0,
  input_tokens INTEGER NOT NULL DEFAULT 0,
  output_tokens INTEGER NOT NULL DEFAULT 0,
  total_tokens INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL,
  UNIQUE (user_id, session_hash, endpoint, day)
);
CREATE INDEX IF NOT EXISTS ai_usage_day_idx ON ai_usage(user_id, day);

-- Conversation memory, always scoped to one person and clearable by them (POST /ai/reset).
CREATE TABLE IF NOT EXISTS ai_conversations (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('user', 'assistant')),
  content TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ai_conversations_user_idx ON ai_conversations(user_id, created_at);

-- Actions the assistant suggests. Nothing here has happened yet: the app only carries a proposal out after the
-- person confirms it (POST /ai/confirm/:id), and then through the ordinary, authorized code path.
CREATE TABLE IF NOT EXISTS ai_proposals (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tool TEXT NOT NULL,
  input_json TEXT NOT NULL,
  summary TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'confirmed', 'cancelled', 'expired')),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  confirmed_at TEXT,
  result_summary TEXT
);
CREATE INDEX IF NOT EXISTS ai_proposals_user_idx ON ai_proposals(user_id, created_at);

-- The runtime kill switch an administrator can flip (src/lib/settings.ts). '1' = on, '0' = off.
INSERT OR IGNORE INTO settings (key, value, updated_at, updated_by)
VALUES ('ai_enabled', '1', '1970-01-01T00:00:00.000Z', NULL);
