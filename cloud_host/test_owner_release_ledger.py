import concurrent.futures
import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path
from owner_release_ledger import initialize,reserve,finalize,status,ReplayBlocked,UnsafeInput

def sample(rev=1,worker='synthetic_only'):
 return {'target_worker':worker,'repository':'research/disposable',
  'branch':'approved/synthetic','source_commit':'a'*40,
  'release_revision':rev,
  'artifact_sha256':hashlib.sha256(str(rev).encode()).hexdigest(),
  'authorization_digest_sha256':hashlib.sha256(('signed'+str(rev)).encode()).hexdigest()}
class LedgerSecurityTest(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory()
  self.addCleanup(self.tmp.cleanup)
  self.db=str(Path(self.tmp.name)/'ledger.sqlite')
  initialize(self.db)
 def test_durable_success_claim_only_once(self):
  r=reserve(self.db,sample(1),1)
  self.assertEqual(r['state'],'reserved')
  self.assertEqual(finalize(self.db,r['claim_id'],'deployed',2)['state'],'deployed')
  with self.assertRaises(ReplayBlocked):finalize(self.db,r['claim_id'],'failed',3)
  with self.assertRaises(ReplayBlocked):reserve(self.db,sample(1),4)
  self.assertEqual(status(self.db)['event_counts'],{'reserved':1,'deployed':1})
 def test_failed_release_requires_new_revision(self):
  r=reserve(self.db,sample(10),10)
  finalize(self.db,r['claim_id'],'failed',11)
  with self.assertRaises(ReplayBlocked):reserve(self.db,sample(10),12)
  self.assertEqual(reserve(self.db,sample(11),13)['release_revision'],11)
 def test_interrupted_claim_consumes_revision(self):
  reserve(self.db,sample(4),10)
  self.assertEqual(status(self.db)['attempts'][0]['state'],'reserved')
  with self.assertRaises(ReplayBlocked):reserve(self.db,sample(4),11)
  self.assertEqual(reserve(self.db,sample(5),12)['state'],'reserved')
 def test_concurrent_reservation_exactly_one_winner(self):
  def worker(i):
   try:reserve(self.db,sample(9),10+i);return 1
   except ReplayBlocked:return 0
  with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
   results=list(ex.map(worker,range(8)))
  self.assertEqual(sum(results),1)
  self.assertEqual(len(status(self.db)['attempts']),1)
 def test_claim_id_recovery_and_invalid_state(self):
  r=reserve(self.db,sample(6),10)
  with self.assertRaises(ReplayBlocked):finalize(self.db,'0'*32,'deployed',11)
  with self.assertRaises(UnsafeInput):finalize(self.db,r['claim_id'],'queued',12)
  self.assertEqual(status(self.db)['attempts'][0]['state'],'reserved')
 def test_invalid_inputs_do_not_open_database(self):
  items=[]
  for key,value in [('target_worker','x;drop'),('source_commit','bad'),
                    ('branch','../../production'),('release_revision',True)]:
   v=sample();v[key]=value;items.append(v)
  a=sample();a['unknown']=True;items.append(a)
  for v in items:
   with self.assertRaises(UnsafeInput):reserve(self.db,v,123)
  self.assertEqual(status(self.db)['attempts'],[])
 def test_independent_worker_revisions(self):
  reserve(self.db,sample(1,'worker_one'),10)
  reserve(self.db,sample(1,'worker_two'),11)
  self.assertEqual(len(status(self.db)['heads']),2)
 def test_lost_ledger_refuses_automatic_recreation(self):
  reserve(self.db,sample(31),11)
  Path(self.db).unlink()
  with self.assertRaises(UnsafeInput):status(self.db)
  with self.assertRaises(UnsafeInput):reserve(self.db,sample(31),12)
  self.assertFalse(Path(self.db).exists())
 def test_initialization_never_overwrites(self):
  with self.assertRaises(UnsafeInput):initialize(self.db)
  self.assertEqual(status(self.db)['heads'],[])
 def test_event_history_is_append_only(self):
  a=reserve(self.db,sample(2),10);finalize(self.db,a['claim_id'],'failed',11)
  b=reserve(self.db,sample(3),12);finalize(self.db,b['claim_id'],'deployed',13)
  with sqlite3.connect(self.db) as conn:
   seq=conn.execute('SELECT revision,event_type FROM release_events ORDER BY event_id').fetchall()
  self.assertEqual(seq,[(2,'reserved'),(2,'failed'),(3,'reserved'),(3,'deployed')])
if __name__=='__main__':unittest.main()
