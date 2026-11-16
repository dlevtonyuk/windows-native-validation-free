-- RESEARCH ONLY: new disposable SQLite/D1 schema, NOT deployed to Cloudflare.
-- Persists ONLY range, state, provider job-id, safe digests/counts and events.
-- Does NOT store credentials, employee identities, timecards, CSV, GPS or payroll amounts.
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS uag_provider_runs (
  period_key TEXT PRIMARY KEY CHECK(length(period_key) BETWEEN 5 AND 80),
  start_unix INTEGER NOT NULL CHECK(start_unix>0),
  end_unix INTEGER NOT NULL CHECK(end_unix>start_unix),
  phase TEXT NOT NULL DEFAULT 'new' CHECK(phase IN ('new','poll','download','complete','review_required','deadletter')),
  zoho_job_id TEXT,
  expiry_ms INTEGER,
  next_due_ms INTEGER NOT NULL DEFAULT 0 CHECK(next_due_ms>=0),
  lease_until_ms INTEGER NOT NULL DEFAULT 0 CHECK(lease_until_ms>=0),
  revision INTEGER NOT NULL DEFAULT 0 CHECK(revision>=0),
  attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count BETWEEN 0 AND 12),
  result_sha256 TEXT,
  aggregate_json TEXT,
  last_error_code TEXT,
  updated_ms INTEGER NOT NULL CHECK(updated_ms>=0),
  CHECK ((phase NOT IN ('poll','download','complete','review_required') OR zoho_job_id IS NOT NULL)),
  CHECK ((phase NOT IN ('complete','review_required') OR result_sha256 IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS uag_provider_due ON uag_provider_runs(phase,next_due_ms,lease_until_ms);
CREATE TABLE IF NOT EXISTS uag_provider_events (
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  period_key TEXT NOT NULL REFERENCES uag_provider_runs(period_key),
  event_kind TEXT NOT NULL CHECK(event_kind IN ('claimed','deferred','export_started','export_ready','reconciled','review_required','deadletter')),
  from_phase TEXT NOT NULL,
  to_phase TEXT NOT NULL,
  revision INTEGER NOT NULL,
  stamped_ms INTEGER NOT NULL
);
CREATE TRIGGER IF NOT EXISTS uag_provider_transition_audit
AFTER UPDATE ON uag_provider_runs
BEGIN
  SELECT CASE
    WHEN NEW.revision<>OLD.revision+1 THEN RAISE(ABORT,'revision_skip')
    WHEN NEW.start_unix<>OLD.start_unix OR NEW.end_unix<>OLD.end_unix OR NEW.period_key<>OLD.period_key THEN RAISE(ABORT,'period_mutation')
    WHEN NEW.updated_ms<OLD.updated_ms THEN RAISE(ABORT,'clock_regression')
    WHEN OLD.phase=NEW.phase AND OLD.lease_until_ms=0 AND NEW.lease_until_ms>0 AND NEW.attempt_count=OLD.attempt_count+1 THEN 1
    WHEN OLD.phase=NEW.phase AND OLD.lease_until_ms>0 AND NEW.updated_ms>OLD.lease_until_ms AND NEW.lease_until_ms>NEW.updated_ms AND NEW.attempt_count=OLD.attempt_count+1 THEN 1
    WHEN OLD.phase=NEW.phase AND OLD.lease_until_ms>0 AND NEW.lease_until_ms=0 AND NEW.attempt_count=OLD.attempt_count THEN 1
    WHEN OLD.phase='new' AND NEW.phase='poll' AND NEW.zoho_job_id IS NOT NULL AND OLD.lease_until_ms>0 AND NEW.lease_until_ms=0 THEN 1
    WHEN OLD.phase='poll' AND NEW.phase='download' AND NEW.zoho_job_id=OLD.zoho_job_id AND NEW.expiry_ms>0 AND OLD.lease_until_ms>0 AND NEW.lease_until_ms=0 THEN 1
    WHEN OLD.phase='download' AND NEW.phase IN ('complete','review_required') AND NEW.result_sha256 IS NOT NULL AND OLD.lease_until_ms>0 AND NEW.lease_until_ms=0 THEN 1
    WHEN NEW.phase='deadletter' AND OLD.phase IN('new','poll','download') AND OLD.lease_until_ms>0 AND NEW.lease_until_ms=0 THEN 1
    ELSE RAISE(ABORT,'unauthorized_phase_transition')
  END;
  INSERT INTO uag_provider_events(period_key,event_kind,from_phase,to_phase,revision,stamped_ms)
  VALUES(NEW.period_key,
    CASE
      WHEN NEW.phase='deadletter' THEN 'deadletter'
      WHEN OLD.phase='new' AND NEW.phase='poll' THEN 'export_started'
      WHEN OLD.phase='poll' AND NEW.phase='download' THEN 'export_ready'
      WHEN OLD.phase='download' AND NEW.phase='complete' THEN 'reconciled'
      WHEN OLD.phase='download' AND NEW.phase='review_required' THEN 'review_required'
      WHEN NEW.lease_until_ms>0 THEN 'claimed'
      ELSE 'deferred'
    END, OLD.phase, NEW.phase, NEW.revision, NEW.updated_ms);
END;
