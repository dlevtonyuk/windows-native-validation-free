-- Dedicated Windows real-device aggregate telemetry only; NOT the UAG or synthetic pilot.
-- No real devices are enrolled in an initial staging deployment.
CREATE TABLE IF NOT EXISTS device_registry (
  device_id TEXT PRIMARY KEY NOT NULL CHECK(length(device_id)=32),
  token_sha256 TEXT NOT NULL UNIQUE CHECK(length(token_sha256)=64),
  active INTEGER NOT NULL DEFAULT 0 CHECK(active IN (0,1)),
  enrolled_ms INTEGER NOT NULL CHECK(enrolled_ms>0),
  comment TEXT NOT NULL DEFAULT 'owner-activated-readonly' CHECK(length(comment)<=64)
);
CREATE TABLE IF NOT EXISTS telemetry_readings (
  device_id TEXT NOT NULL,
  sample_id TEXT NOT NULL CHECK(length(sample_id)=36),
  observed_ms INTEGER NOT NULL CHECK(observed_ms>0),
  received_ms INTEGER NOT NULL CHECK(received_ms>0),
  evidence_kind TEXT NOT NULL CHECK(evidence_kind='aggregate_windows_readonly'),
  cpu_used_pct REAL CHECK(cpu_used_pct IS NULL OR (cpu_used_pct>=0 AND cpu_used_pct<=100)),
  ram_used_pct REAL NOT NULL CHECK(ram_used_pct>=0 AND ram_used_pct<=100),
  ram_total_mb INTEGER NOT NULL CHECK(ram_total_mb BETWEEN 128 AND 4194304),
  ram_available_mb INTEGER NOT NULL CHECK(ram_available_mb>=0 AND ram_available_mb<=ram_total_mb),
  commit_used_pct REAL CHECK(commit_used_pct IS NULL OR (commit_used_pct>=0 AND commit_used_pct<=100)),
  process_count INTEGER NOT NULL CHECK(process_count BETWEEN 1 AND 100000),
  PRIMARY KEY(device_id,sample_id),
  FOREIGN KEY(device_id) REFERENCES device_registry(device_id)
);
CREATE INDEX IF NOT EXISTS telemetry_readings_device_received ON telemetry_readings(device_id,received_ms DESC);
-- Retention is enforced by a separately activated, scheduled Worker handler.