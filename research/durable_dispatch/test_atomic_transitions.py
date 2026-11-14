"""Synthetic-only real SQLite atomic audit and expired-attempt tests."""
import pathlib
import sqlite3
import unittest

ROOT=pathlib.Path(__file__).resolve().parent
SCHEMA=(ROOT/"schema.sql").read_text(encoding="utf-8")
FIXTURES=(ROOT/"fixtures.sql").read_text(encoding="utf-8")

class AuditAtomicity(unittest.TestCase):
 def setUp(self):
  self.db=sqlite3.connect(":memory:")
  self.db.executescript(SCHEMA)
  self.db.executescript(FIXTURES)
 def tearDown(self):self.db.close()
 def query(self,sql,*args):return self.db.execute(sql,args).fetchall()
 def test_preexisting_claims_are_audited(self):
  self.assertEqual(self.query("SELECT job_id FROM dispatch_events WHERE kind='claimed' ORDER BY job_id"),
    [('exhausted',),('recovered',)])
 def test_update_and_event_are_one_transaction(self):
  self.db.execute("UPDATE dispatch_jobs SET state='running',attempts=1,lease_until_ms=100000,last_transition_ms=500 WHERE job_id='readok'")
  x=self.query("SELECT state,attempts FROM dispatch_jobs WHERE job_id='readok'")
  events=self.query("SELECT kind,stamp_ms,attempt FROM dispatch_events WHERE job_id='readok'")
  self.assertEqual(x,[('running',1)])
  self.assertEqual(events,[('claimed',500,1)])
 def test_event_insertion_failure_rolls_back_job_transition(self):
  self.db.execute("UPDATE dispatch_jobs SET state='running',attempts=1,lease_until_ms=100000,last_transition_ms=500 WHERE job_id='readok'")
  self.db.executescript("""CREATE TRIGGER refuse_audit BEFORE INSERT ON dispatch_events
    WHEN NEW.kind='succeeded' BEGIN SELECT RAISE(ABORT,'injected_audit_failure'); END;""")
  with self.assertRaisesRegex(sqlite3.DatabaseError,"injected_audit_failure"):
   self.db.execute("UPDATE dispatch_jobs SET state='succeeded',completed_ms=800,result_sha256=?,lease_until_ms=NULL,last_transition_ms=800 WHERE job_id='readok'",("a"*64,))
  self.assertEqual(self.query("SELECT state,completed_ms,result_sha256 FROM dispatch_jobs WHERE job_id='readok'"),[('running',None,None)])
  self.assertEqual(self.query("SELECT kind FROM dispatch_events WHERE job_id='readok'"),[('claimed',)])
 def test_expired_last_attempt_deadletter_audited(self):
  self.db.execute("UPDATE dispatch_jobs SET state='deadletter',last_error='expired_mock_lease_attempts_exhausted',lease_until_ms=NULL,last_transition_ms=1000 WHERE job_id='exhausted'")
  self.assertEqual(self.query("SELECT state,attempts FROM dispatch_jobs WHERE job_id='exhausted'"),[('deadletter',2)])
  self.assertEqual(self.query("SELECT kind FROM dispatch_events WHERE job_id='exhausted'"),[('claimed',),('deadletter',)])
 def test_recovered_claim_logged_atomically(self):
  self.db.execute("UPDATE dispatch_jobs SET state='queued',last_error='expired_mock_lease',lease_until_ms=NULL,last_transition_ms=1000 WHERE job_id='recovered'")
  self.assertEqual(self.query("SELECT kind FROM dispatch_events WHERE job_id='recovered'"),[('claimed',),('lease_recovered',)])
 def test_invalid_state_transition_rejected(self):
  with self.assertRaisesRegex(sqlite3.DatabaseError,"illegal_job_transition"):
   self.db.execute("UPDATE dispatch_jobs SET state='succeeded',completed_ms=1000,result_sha256=?,last_transition_ms=1000 WHERE job_id='readok'",("a"*64,))
  self.assertEqual(self.query("SELECT state FROM dispatch_jobs WHERE job_id='readok'"),[('queued',)])
 def test_missing_transition_clock_denied(self):
  with self.assertRaisesRegex(sqlite3.DatabaseError,"missing_transition_time"):
   self.db.execute("UPDATE dispatch_jobs SET state='running',attempts=1,lease_until_ms=1000 WHERE job_id='readok'")
  self.assertEqual(self.query("SELECT state,attempts FROM dispatch_jobs WHERE job_id='readok'"),[('queued',0)])
 def test_non_synthetic_routes_remain_unexecuted(self):
  self.assertEqual(self.query("SELECT job_id,state,attempts FROM dispatch_jobs WHERE route<>'cloud_readonly_mock' ORDER BY job_id"),
   [('connectorheld','queued',0),('deviceheld','queued',0),('writeheld','queued',0)])
if __name__=="__main__":unittest.main()
