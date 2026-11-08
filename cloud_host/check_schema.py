"""Offline SQLite syntax check for D1 schema; no real Cloudflare account used."""
from pathlib import Path
import sqlite3

sql = (Path(__file__).resolve().parent / "schema.sql").read_text(encoding="utf-8")
db = sqlite3.connect(":memory:")
try:
    db.executescript(sql)
    columns = [row[1] for row in db.execute("PRAGMA table_info(jobs)")]
    required = {"job_id", "capability", "operation", "device", "payload_json",
                "state", "created_at", "lease_until", "result_json"}
    assert set(columns) == required
    indexes = list(db.execute("PRAGMA index_list(jobs)"))
    assert len(indexes) >= 2

    policy_columns = [row[1] for row in db.execute("PRAGMA table_info(owner_policy_state)")]
    assert set(policy_columns) == {"id", "highest_revision", "payload_sha256"}, (
        "Owner policy anti-rollback state table missing or malformed"
    )
    # Execute the EXACT SQL used by cloud_host/worker.mjs, not a hand-waved
    # equivalent, to verify SQLite/D1-compatible monotonic update semantics.
    upsert = (
        "INSERT INTO owner_policy_state (id,highest_revision,payload_sha256) VALUES (1,?,?) "
        "ON CONFLICT(id) DO UPDATE SET "
        "highest_revision=excluded.highest_revision,payload_sha256=excluded.payload_sha256 "
        "WHERE excluded.highest_revision > owner_policy_state.highest_revision OR "
        "(excluded.highest_revision = owner_policy_state.highest_revision AND "
        "excluded.payload_sha256 = owner_policy_state.payload_sha256) "
        "RETURNING highest_revision"
    )
    def accept(revision: int, digest: str):
        return db.execute(upsert, (revision, digest)).fetchone()
    assert accept(1, "digest_v1") == (1,)
    assert accept(1, "digest_v1") == (1,)
    assert accept(1, "tampered_same_revision") is None
    assert accept(2, "digest_v2") == (2,)
    assert accept(1, "digest_v1") is None
    assert accept(2, "tampered_same_revision") is None
    assert accept(3, "digest_v3") == (3,)
    assert db.execute(
        "SELECT highest_revision,payload_sha256 FROM owner_policy_state WHERE id=1"
    ).fetchone() == (3, "digest_v3")
    print("D1_OWNER_POLICY_ANTI_ROLLBACK_SQL_PASSED")
    print("D1_SCHEMA_SQLITE_PASSED")
finally:
    db.close()
