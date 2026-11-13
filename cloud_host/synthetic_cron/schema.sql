-- Synthetic-only additive D1 schema; no personal or business information.
-- Applied only to disposable local D1 until explicit separate deployment approval.
CREATE TABLE IF NOT EXISTS synthetic_cron_receipts (
  slot_ms INTEGER PRIMARY KEY CHECK(slot_ms > 0),
  kind TEXT NOT NULL CHECK(kind = 'synthetic_heartbeat'),
  scheduled_at_ms INTEGER NOT NULL CHECK(scheduled_at_ms >= slot_ms AND scheduled_at_ms < slot_ms + 3600000)
);
