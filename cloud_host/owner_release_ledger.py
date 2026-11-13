"""OFFLINE trusted-runner research: one-use SQLite release authorizations.
Does not validate signatures; the adjacent JS guard MUST verify the signature
and artifact bytes first. Never run in assistant-controlled production CI.
"""
import argparse
import json
import re
import secrets
import sqlite3
import sys
import time
from pathlib import Path

SHA256=re.compile(r'^[0-9a-f]{64}$')
SHA40=re.compile(r'^[0-9a-f]{40}$')
REPO=re.compile(r'^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$')
NAME=re.compile(r'^[a-zA-Z0-9_-]{3,128}$')
BRANCH=re.compile(r'^[A-Za-z0-9_.\-/]{1,200}$')
RECEIPT=re.compile(r'^[0-9a-f]{32}$')
SCHEMA="""
CREATE TABLE IF NOT EXISTS release_heads (
 target_worker TEXT PRIMARY KEY,
 highest_revision INTEGER NOT NULL CHECK(highest_revision >= 1),
 latest_artifact_sha256 TEXT NOT NULL,
 latest_commit TEXT NOT NULL,
 updated_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS release_attempts (
 claim_id TEXT PRIMARY KEY,
 target_worker TEXT NOT NULL,
 revision INTEGER NOT NULL,
 repository TEXT NOT NULL,
 branch TEXT NOT NULL,
 source_commit TEXT NOT NULL,
 artifact_sha256 TEXT NOT NULL,
 authorization_digest_sha256 TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('reserved','deployed','failed')),
 created_ms INTEGER NOT NULL,
 finalized_ms INTEGER,
 UNIQUE(target_worker,revision)
);
CREATE TABLE IF NOT EXISTS release_events (
 event_id INTEGER PRIMARY KEY AUTOINCREMENT,
 target_worker TEXT NOT NULL,
 revision INTEGER NOT NULL,
 event_type TEXT NOT NULL CHECK(event_type IN ('reserved','deployed','failed')),
 claim_id TEXT NOT NULL,
 created_ms INTEGER NOT NULL
);
"""
class UnsafeInput(ValueError): pass
class ReplayBlocked(Exception): pass

def checked_release(v):
 if not isinstance(v,dict) or set(v)!={'target_worker','repository','branch',
    'source_commit','release_revision','artifact_sha256','authorization_digest_sha256'}:
  raise UnsafeInput('release_receipt_schema')
 for key,pat in [('target_worker',NAME),('repository',REPO),('branch',BRANCH),
                 ('source_commit',SHA40),('artifact_sha256',SHA256),
                 ('authorization_digest_sha256',SHA256)]:
  if not isinstance(v[key],str) or not pat.fullmatch(v[key]):raise UnsafeInput('invalid_'+key)
 if type(v['release_revision']) is not int or not (1<=v['release_revision']<=9007199254740991):
  raise UnsafeInput('invalid_revision')
 if v['branch'].startswith(('-', '/')) or '..' in v['branch']:
  raise UnsafeInput('invalid_branch')
 return v

def initialize(path):
 """Explicit owner-controlled init; no automatic empty-DB recovery."""
 if not path or not isinstance(path,str) or not Path(path).parent.is_dir():
  raise UnsafeInput('invalid_ledger_path')
 if Path(path).exists() or Path(path).is_symlink():
  raise UnsafeInput('ledger_already_exists')
 db=sqlite3.connect(path,timeout=5,isolation_level=None)
 try:
  db.execute('PRAGMA synchronous=FULL')
  db.executescript(SCHEMA)
  return {'state':'initialized'}
 finally:db.close()

def connect(path):
 if not path or not isinstance(path,str) or not Path(path).is_file() or Path(path).is_symlink():
  raise UnsafeInput('ledger_missing_or_untrusted')
 from urllib.parse import quote
 uri='file:'+quote(Path(path).resolve().as_posix(),safe='/:')+'?mode=rw'
 conn=sqlite3.connect(uri,timeout=5,isolation_level=None,uri=True)
 conn.execute('PRAGMA busy_timeout=5000')
 conn.execute('PRAGMA synchronous=FULL')
 conn.execute('PRAGMA foreign_keys=ON')
 tables={name for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
 if not {'release_heads','release_attempts','release_events'}.issubset(tables):
  conn.close()
  raise UnsafeInput('ledger_schema_missing')
 return conn

def assert_consistent_ledger(db):
 """Fail closed when stored revision history and high-water heads disagree.
 This detects accidental/tampered inconsistent SQLite state; a writer able
 to rewrite every table can still forge consistent records. NOT immutable.
 Caller MUST hold a SQLite read/write transaction for a consistent snapshot.
 """
 head_mismatch=db.execute("""
 SELECT 1 FROM release_heads h WHERE
 NOT EXISTS (
  SELECT 1 FROM release_attempts a
  WHERE a.target_worker=h.target_worker AND a.revision=h.highest_revision
   AND a.artifact_sha256=h.latest_artifact_sha256
   AND a.source_commit=h.latest_commit
 ) OR EXISTS (
  SELECT 1 FROM release_attempts a
  WHERE a.target_worker=h.target_worker AND a.revision>h.highest_revision
 ) LIMIT 1
 """).fetchone()
 orphan_attempt=db.execute("""
 SELECT 1 FROM release_attempts a WHERE NOT EXISTS (
  SELECT 1 FROM release_heads h WHERE h.target_worker=a.target_worker
 ) LIMIT 1
 """).fetchone()
 missing_event=db.execute("""
 SELECT 1 FROM release_attempts a WHERE
 NOT EXISTS (
  SELECT 1 FROM release_events e WHERE e.claim_id=a.claim_id
   AND e.target_worker=a.target_worker AND e.revision=a.revision
   AND e.event_type='reserved'
 ) OR (a.state<>'reserved' AND NOT EXISTS (
  SELECT 1 FROM release_events e WHERE e.claim_id=a.claim_id
   AND e.target_worker=a.target_worker AND e.revision=a.revision
   AND e.event_type=a.state
 )) LIMIT 1
 """).fetchone()
 orphan_event=db.execute("""
 SELECT 1 FROM release_events e WHERE NOT EXISTS (
  SELECT 1 FROM release_attempts a WHERE a.claim_id=e.claim_id
   AND a.target_worker=e.target_worker AND a.revision=e.revision
 ) LIMIT 1
 """).fetchone()
 if any((head_mismatch,orphan_attempt,missing_event,orphan_event)):
  raise UnsafeInput('ledger_history_inconsistent')


def reserve(path,receipt,now_ms=None):
 a=checked_release(receipt)
 stamp=int(time.time()*1000) if now_ms is None else now_ms
 if type(stamp) is not int or stamp<0:raise UnsafeInput('invalid_time')
 claim=secrets.token_hex(16)
 db=connect(path)
 try:
  db.execute('BEGIN IMMEDIATE')
  assert_consistent_ledger(db)
  row=db.execute('SELECT highest_revision FROM release_heads WHERE target_worker=?',(a['target_worker'],)).fetchone()
  if row and a['release_revision']<=row[0]:raise ReplayBlocked('revision_consumed')
  db.execute('INSERT INTO release_heads (target_worker,highest_revision,latest_artifact_sha256,latest_commit,updated_ms) VALUES(?,?,?,?,?) '
    'ON CONFLICT(target_worker) DO UPDATE SET highest_revision=excluded.highest_revision,'
    'latest_artifact_sha256=excluded.latest_artifact_sha256,latest_commit=excluded.latest_commit,updated_ms=excluded.updated_ms '
    'WHERE excluded.highest_revision>release_heads.highest_revision',
    (a['target_worker'],a['release_revision'],a['artifact_sha256'],a['source_commit'],stamp))
  db.execute('INSERT INTO release_attempts (claim_id,target_worker,revision,repository,branch,source_commit,artifact_sha256,authorization_digest_sha256,state,created_ms) VALUES(?,?,?,?,?,?,?,?,?,?)',
    (claim,a['target_worker'],a['release_revision'],a['repository'],a['branch'],a['source_commit'],a['artifact_sha256'],a['authorization_digest_sha256'],'reserved',stamp))
  db.execute('INSERT INTO release_events (target_worker,revision,event_type,claim_id,created_ms) VALUES(?,?,?,?,?)',
    (a['target_worker'],a['release_revision'],'reserved',claim,stamp))
  db.execute('COMMIT')
  return {'state':'reserved','claim_id':claim,'target_worker':a['target_worker'],
          'release_revision':a['release_revision'],'artifact_sha256':a['artifact_sha256']}
 except Exception:
  db.execute('ROLLBACK')
  raise
 finally:db.close()

def finalize(path,claim,result,now_ms=None):
 if not isinstance(claim,str) or not RECEIPT.fullmatch(claim):raise UnsafeInput('bad_claim')
 if result not in ('deployed','failed'):raise UnsafeInput('unsupported_result')
 stamp=int(time.time()*1000) if now_ms is None else now_ms
 if type(stamp) is not int or stamp<0:raise UnsafeInput('invalid_time')
 db=connect(path)
 try:
  db.execute('BEGIN IMMEDIATE')
  assert_consistent_ledger(db)
  row=db.execute('SELECT target_worker,revision FROM release_attempts WHERE claim_id=? AND state=?',(claim,'reserved')).fetchone()
  if row is None:raise ReplayBlocked('claim_absent_or_consumed')
  db.execute('UPDATE release_attempts SET state=?,finalized_ms=? WHERE claim_id=? AND state=?',(result,stamp,claim,'reserved'))
  db.execute('INSERT INTO release_events (target_worker,revision,event_type,claim_id,created_ms) VALUES(?,?,?,?,?)',
    (row[0],row[1],result,claim,stamp))
  db.execute('COMMIT')
  return {'state':result,'target_worker':row[0],'release_revision':row[1]}
 except Exception:
  db.execute('ROLLBACK')
  raise
 finally:db.close()

def status(path):
 db=connect(path)
 try:
  db.execute('BEGIN')
  assert_consistent_ledger(db)
  heads=db.execute('SELECT target_worker,highest_revision,latest_artifact_sha256 FROM release_heads ORDER BY target_worker').fetchall()
  attempts=db.execute('SELECT target_worker,revision,state FROM release_attempts ORDER BY target_worker,revision').fetchall()
  events=db.execute('SELECT event_type,COUNT(*) FROM release_events GROUP BY event_type').fetchall()
  result={'heads':[dict(target_worker=t,highest_revision=r,artifact_sha256=d) for t,r,d in heads],
     'attempts':[dict(target_worker=t,revision=r,state=s) for t,r,s in attempts],
     'event_counts':{k:v for k,v in events}}
  db.execute('COMMIT')
  return result
 except Exception:
  db.execute('ROLLBACK')
  raise
 finally:db.close()

def main():
 p=argparse.ArgumentParser(description='OFFLINE only: no deployments')
 p.add_argument('action',choices=('init','reserve','finalize','status'))
 p.add_argument('--db',required=True)
 p.add_argument('--claim-id')
 p.add_argument('--result',choices=('deployed','failed'))
 a=p.parse_args()
 try:
  if a.action=='init':res=initialize(a.db)
  elif a.action=='reserve':res=reserve(a.db,json.loads(sys.stdin.read(4096)))
  elif a.action=='finalize':res=finalize(a.db,a.claim_id,a.result)
  else:res=status(a.db)
  print(json.dumps(res,separators=(',',':')))
 except (UnsafeInput,ReplayBlocked,json.JSONDecodeError,sqlite3.Error) as exc:
  print(json.dumps({'error':str(exc)}),file=sys.stderr)
  return 2
 return 0

if __name__=='__main__':sys.exit(main())
