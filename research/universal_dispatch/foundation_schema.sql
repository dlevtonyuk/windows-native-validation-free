-- UAG universal foundation schema v1. OWNER-APPROVED INFRASTRUCTURE ONLY.
-- For the newly isolated UAG D1 database. No business data/identities/secrets.
-- An assistant-editable Worker/D1 database IS NOT an owner-exclusive effect broker.
-- All capability activations are impossible in this schema (CHECK enabled = 0).
CREATE TABLE IF NOT EXISTS foundation_meta (
  id INTEGER PRIMARY KEY CHECK(id=1),
  schema_version INTEGER NOT NULL CHECK(schema_version=1),
  execution_mode TEXT NOT NULL CHECK(execution_mode='FOUNDATION_INERT'),
  created_ms INTEGER NOT NULL CHECK(created_ms>0)
);
INSERT OR IGNORE INTO foundation_meta(id,schema_version,execution_mode,created_ms)
VALUES (1,1,'FOUNDATION_INERT',CAST(strftime('%s','now') AS INTEGER)*1000);

CREATE TABLE IF NOT EXISTS foundation_capabilities (
  capability_id TEXT PRIMARY KEY CHECK(length(capability_id) BETWEEN 3 AND 64),
  route TEXT NOT NULL CHECK(route IN ('cloud_readonly','connector_readonly','device_local','owner_guarded_effect')),
  enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled=0),
  status TEXT NOT NULL DEFAULT 'planned' CHECK(status IN ('planned','unavailable','awaiting_owner')),
  owner_activation_revision INTEGER NOT NULL DEFAULT 0 CHECK(owner_activation_revision=0),
  metadata_only INTEGER NOT NULL DEFAULT 1 CHECK(metadata_only=1)
);
CREATE TABLE IF NOT EXISTS foundation_jobs (
  job_id TEXT PRIMARY KEY CHECK(length(job_id) BETWEEN 5 AND 80),
  capability_id TEXT NOT NULL REFERENCES foundation_capabilities(capability_id),
  source_id TEXT NOT NULL CHECK(length(source_id) BETWEEN 3 AND 80),
  idempotency_key TEXT NOT NULL CHECK(length(idempotency_key) BETWEEN 3 AND 128),
  due_ms INTEGER NOT NULL CHECK(due_ms>0),
  priority INTEGER NOT NULL DEFAULT 2 CHECK(priority BETWEEN 0 AND 3),
  state TEXT NOT NULL DEFAULT 'held' CHECK(state IN ('held','cancelled')),
  created_ms INTEGER NOT NULL CHECK(created_ms>0),
  last_review_ms INTEGER,
  request_sha256 TEXT CHECK(request_sha256 IS NULL OR length(request_sha256)=64),
  UNIQUE(source_id,idempotency_key)
);
CREATE INDEX IF NOT EXISTS foundation_held_due ON foundation_jobs(state,due_ms,priority);
CREATE TABLE IF NOT EXISTS foundation_ticks (
  slot_ms INTEGER PRIMARY KEY CHECK(slot_ms>0),
  triggered_ms INTEGER NOT NULL CHECK(triggered_ms>0),
  recorded_ms INTEGER NOT NULL CHECK(recorded_ms>0),
  held_due_count INTEGER NOT NULL CHECK(held_due_count>=0),
  mode TEXT NOT NULL CHECK(mode='FOUNDATION_INERT')
);
CREATE TABLE IF NOT EXISTS foundation_audit (
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_kind TEXT NOT NULL CHECK(event_kind IN ('foundation_created','capability_catalogued','job_held','validation_failed')),
  capability_id TEXT,
  event_ms INTEGER NOT NULL CHECK(event_ms>0),
  detail_code TEXT NOT NULL CHECK(length(detail_code)<=100)
);
INSERT OR IGNORE INTO foundation_capabilities(capability_id,route,status)
VALUES ('cloud_read_adapter','cloud_readonly','awaiting_owner');
INSERT OR IGNORE INTO foundation_capabilities(capability_id,route,status)
VALUES ('chatgpt_connector','connector_readonly','unavailable');
INSERT OR IGNORE INTO foundation_capabilities(capability_id,route,status)
VALUES ('device_service','device_local','awaiting_owner');
INSERT OR IGNORE INTO foundation_capabilities(capability_id,route,status)
VALUES ('owner_effect_broker','owner_guarded_effect','awaiting_owner');
