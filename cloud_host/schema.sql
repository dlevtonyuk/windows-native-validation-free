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
