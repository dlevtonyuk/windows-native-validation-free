-- DISABLED owner-policy staging only; no active grant writes or business jobs.
CREATE TABLE IF NOT EXISTS owner_policy_stage (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  revision INTEGER NOT NULL CHECK (revision >= 1),
  policy_json TEXT NOT NULL,
  signature_b64 TEXT NOT NULL,
  digest_hex TEXT NOT NULL,
  actor_sha256 TEXT NOT NULL,
  staged_at INTEGER NOT NULL
);
