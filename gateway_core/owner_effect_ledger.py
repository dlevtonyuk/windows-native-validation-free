"""Offline, trusted-adapter-side research ledger for one-use owner effects.
No network, no executable effect, no cloud credentials. SQLite is not tamper proof.
The trusted host must control this file and invoke only after Ed25519 grant verify.
"""
import json
import re
import sqlite3
import sys
import time
from pathlib import Path
from urllib.parse import quote

H64=re.compile(r'^[a-f0-9]{64}$')
JOB=re.compile(r'^[a-f0-9]{32}$')
SCHEMA='''
CREATE TABLE IF NOT EXISTS active_grant (
 id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL CHECK(revision>=1),
 grant_sha256 TEXT NOT NULL,max_claims INTEGER NOT NULL CHECK(max_claims>0),
 claimed INTEGER NOT NULL DEFAULT 0 CHECK(claimed>=0 AND claimed<=max_claims));
CREATE TABLE IF NOT EXISTS effect_claims (
 job_id TEXT PRIMARY KEY,grant_sha256 TEXT NOT NULL,revision INTEGER NOT NULL,
 payload_sha256 TEXT NOT NULL,state TEXT NOT NULL
 CHECK(state IN ('reserved','succeeded','failed')),
 created_ms INTEGER NOT NULL,finalized_ms INTEGER);
'''
class Denied(Exception):pass

def _hash(s):return type(s) is str and bool(H64.fullmatch(s))
def _rev(n):return type(n) is int and 1<=n<=9007199254740991
def _budget(n):return type(n) is int and 1<=n<=10000

def initialize(path):
 p=Path(path)
 if not p.parent.is_dir() or p.exists() or p.is_symlink():raise Denied('ledger_not_safely_initializable')
 db=sqlite3.connect(str(p),isolation_level=None,timeout=5)
 try:
  db.execute('PRAGMA synchronous=FULL')
  db.executescript(SCHEMA)
 finally:db.close()

def connect(path):
 p=Path(path)
 if not p.is_file() or p.is_symlink():raise Denied('trusted_ledger_unavailable')
 db=sqlite3.connect('file:'+quote(p.resolve().as_posix(),safe='/:')+'?mode=rw',uri=True,timeout=5,isolation_level=None)
 db.execute('PRAGMA synchronous=FULL')
 tables={row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
 if not {'active_grant','effect_claims'}.issubset(tables):
  db.close();raise Denied('trusted_ledger_schema_missing')
 return db

def activate(path,revision,grant_sha256,max_claims):
 """Trusted host only; caller MUST have verified owner signature and scope."""
 if not _rev(revision) or not _hash(grant_sha256) or not _budget(max_claims):raise Denied('invalid_owner_activation')
 db=connect(path)
 try:
  db.execute('BEGIN IMMEDIATE')
  current=db.execute('SELECT revision FROM active_grant WHERE id=1').fetchone()
  if current and current[0]>=revision:raise Denied('stale_activation_revision')
  db.execute('INSERT INTO active_grant(id,revision,grant_sha256,max_claims,claimed) VALUES(1,?,?,?,0) '
             'ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,grant_sha256=excluded.grant_sha256,'
             'max_claims=excluded.max_claims,claimed=0',(revision,grant_sha256,max_claims))
  db.execute('COMMIT')
  return {'active_revision':revision,'remaining_claims':max_claims}
 except Exception:
  db.execute('ROLLBACK');raise
 finally:db.close()

def reserve(path,job_id,grant_sha256,revision,max_claims,payload_sha256,now_ms=None):
 if (type(job_id) is not str or not JOB.fullmatch(job_id) or not _hash(grant_sha256) or
     not _hash(payload_sha256) or not _rev(revision) or not _budget(max_claims)):
  raise Denied('invalid_effect_claim')
 stamp=int(time.time()*1000) if now_ms is None else now_ms
 if type(stamp) is not int or stamp<=0:raise Denied('invalid_clock')
 db=connect(path)
 try:
  db.execute('BEGIN IMMEDIATE')
  row=db.execute('SELECT revision,grant_sha256,max_claims,claimed FROM active_grant WHERE id=1').fetchone()
  if not row or row[:3]!=(revision,grant_sha256,max_claims):
   raise Denied('owner_grant_not_active')
  actual=db.execute('SELECT COUNT(*) FROM effect_claims WHERE revision=? AND grant_sha256=?',(revision,grant_sha256)).fetchone()[0]
  if actual!=row[3]:raise Denied('ledger_history_inconsistent')
  if row[3]>=row[2]:raise Denied('grant_budget_exhausted')
  if db.execute('SELECT 1 FROM effect_claims WHERE job_id=?',(job_id,)).fetchone():
   raise Denied('effect_replay_blocked')
  db.execute('INSERT INTO effect_claims(job_id,grant_sha256,revision,payload_sha256,state,created_ms) '
             "VALUES(?,?,?,?,'reserved',?)",(job_id,grant_sha256,revision,payload_sha256,stamp))
  db.execute('UPDATE active_grant SET claimed=claimed+1 WHERE id=1')
  db.execute('COMMIT')
  return {'state':'reserved','job_id':job_id}
 except Exception:
  db.execute('ROLLBACK');raise
 finally:db.close()

def finalize(path,job_id,outcome,now_ms=None):
 if type(job_id) is not str or not JOB.fullmatch(job_id) or outcome not in ('succeeded','failed'):
  raise Denied('invalid_completion')
 stamp=int(time.time()*1000) if now_ms is None else now_ms
 if type(stamp) is not int or stamp<=0:raise Denied('invalid_clock')
 db=connect(path)
 try:
  db.execute('BEGIN IMMEDIATE')
  row=db.execute('SELECT state FROM effect_claims WHERE job_id=?',(job_id,)).fetchone()
  if row!=('reserved',):raise Denied('claim_already_closed_or_missing')
  db.execute('UPDATE effect_claims SET state=?,finalized_ms=? WHERE job_id=?',(outcome,stamp,job_id))
  db.execute('COMMIT')
  return {'state':outcome,'job_id':job_id}
 except Exception:
  db.execute('ROLLBACK');raise
 finally:db.close()

def status(path):
 db=connect(path)
 try:
  db.execute('BEGIN')
  row=db.execute('SELECT revision,grant_sha256,max_claims,claimed FROM active_grant WHERE id=1').fetchone()
  if row:
   old=db.execute('SELECT COUNT(*) FROM effect_claims WHERE revision=? AND grant_sha256=?',(row[0],row[1])).fetchone()[0]
   if row[3]!=old or row[3]>row[2]:raise Denied('ledger_history_inconsistent')
  claims=db.execute('SELECT job_id,revision,state FROM effect_claims ORDER BY created_ms,job_id').fetchall()
  db.execute('COMMIT')
  return {'active':dict(zip(('revision','grant_sha256','max_claims','claimed'),row)) if row else None,
          'claims':[dict(zip(('job_id','revision','state'),x)) for x in claims]}
 except Exception:
  db.execute('ROLLBACK');raise
 finally:db.close()

if __name__=='__main__':
 # Harness intentionally exposes no command interface for remotely submitted jobs.
 # The host process imports vetted methods in an authenticated, trusted context.
 print('OFFLINE_LIBRARY_ONLY',file=sys.stderr)
 sys.exit(2)
