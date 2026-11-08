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
    print("D1_SCHEMA_SQLITE_PASSED")
finally:
    db.close()
