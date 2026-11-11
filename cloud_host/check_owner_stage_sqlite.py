# Verify atomic staging replay guard against real SQLite, not a mock.
from pathlib import Path
import sqlite3
db=sqlite3.connect(':memory:')
db.executescript(Path(__file__).with_name('schema_stage.sql').read_text())
stmt="""INSERT INTO owner_policy_stage
(id,revision,policy_json,signature_b64,digest_hex,actor_sha256,staged_at)
VALUES(1,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,
policy_json=excluded.policy_json,signature_b64=excluded.signature_b64,
digest_hex=excluded.digest_hex,actor_sha256=excluded.actor_sha256,
staged_at=excluded.staged_at
WHERE excluded.revision>owner_policy_stage.revision
RETURNING revision,digest_hex"""
def stage(v):
 return db.execute(stmt,(v,'{}','sig','digest'+str(v),'actor',123)).fetchone()
assert stage(1)==(1,'digest1')
assert stage(1) is None
assert stage(3)==(3,'digest3')
assert stage(2) is None
assert db.execute('SELECT revision,digest_hex FROM owner_policy_stage').fetchone()==(3,'digest3')
assert db.execute('SELECT COUNT(*) FROM owner_policy_stage').fetchone()[0]==1
print('OWNER_STAGE_SQLITE_CAS_REPLAY_PASSED')
