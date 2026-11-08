-- Cloudflare D1 (SQLite) schema. Generic messages only: no PII, secrets,
-- payroll information, raw diagnostics, or confidential payloads.
CREATE TABLE IF NOT EXISTS jobs (
  job_id TEXT PRIMARY KEY NOT NULL,
  capability TEXT NOT NULL,
  operation TEXT NOT NULL,
  device TEXT NOT NULL,
  payload_json TEXT NOT NULL DEFAULT '{}',
  state TEXT NOT NULL CHECK (state IN ('queued','leased','succeeded','failed','interrupted')),
  created_at INTEGER NOT NULL,
  lease_until INTEGER,
  result_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_jobs_device_state_created
  ON jobs(device, state, created_at);
CREATE INDEX IF NOT EXISTS idx_jobs_lease
  ON jobs(state, lease_until);

-- Owner-policy revision high watermark. Prototype protection against
-- reusing older owner-signed capability grants after a newer one is observed.
-- Backups, independent owner identity and anti-tamper audit still required.
CREATE TABLE IF NOT EXISTS owner_policy_state (
  id INTEGER PRIMARY KEY NOT NULL CHECK (id = 1),
  highest_revision INTEGER NOT NULL CHECK (highest_revision >= 1),
  payload_sha256 TEXT NOT NULL
);
