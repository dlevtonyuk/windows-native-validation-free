-- RESEARCH ONLY: disposable D1 / workerd. No account data, provider tokens or real business effects.
CREATE TABLE IF NOT EXISTS dispatch_ticks (
  slot_ms INTEGER PRIMARY KEY CHECK(slot_ms > 0),
  triggered_ms INTEGER NOT NULL CHECK(triggered_ms >= slot_ms AND triggered_ms < slot_ms + 3600000),
  dispatch_type TEXT NOT NULL DEFAULT 'synthetic_only' CHECK(dispatch_type='synthetic_only')
);
CREATE TABLE IF NOT EXISTS dispatch_jobs (
  job_id TEXT PRIMARY KEY,
  route TEXT NOT NULL CHECK(route IN('cloud_readonly_mock','connector_readonly','device_local','owner_guarded_write')),
  operation TEXT NOT NULL CHECK(operation IN('observe_ready','fail_first','device_probe','connector_probe','effect_probe')),
  due_ms INTEGER NOT NULL CHECK(due_ms >= 0),
  state TEXT NOT NULL CHECK(state IN('queued','running','succeeded','deadletter','waiting_for_external_executor')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
  max_attempts INTEGER NOT NULL DEFAULT 2 CHECK(max_attempts BETWEEN 1 AND 5),
  lease_until_ms INTEGER,
  completed_ms INTEGER,
  result_sha256 TEXT,
  last_error TEXT,
  CHECK((state != 'running') OR lease_until_ms IS NOT NULL),
  CHECK((state != 'succeeded') OR (completed_ms IS NOT NULL AND result_sha256 IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS dispatch_due_idx ON dispatch_jobs(state,route,due_ms,job_id);
CREATE TABLE IF NOT EXISTS dispatch_events (
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id TEXT NOT NULL REFERENCES dispatch_jobs(job_id),
  kind TEXT NOT NULL CHECK(kind IN('claimed','succeeded','retry_queued','deadletter','lease_recovered')),
  stamp_ms INTEGER NOT NULL,
  attempt INTEGER NOT NULL CHECK(attempt >= 1)
);
