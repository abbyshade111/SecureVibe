-- File uploads (src/features/uploads). The table is always created so the download route, quota checks and
-- account export/delete work even while the feature is switched off; nothing is written unless it is turned on.
-- The actual file bytes live at DATA_DIR/uploads/<id>, never at a path built from the user-supplied name.
CREATE TABLE IF NOT EXISTS uploads (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  original_name TEXT NOT NULL,
  mime TEXT NOT NULL,
  size INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS uploads_owner_idx ON uploads(owner_id, created_at);
