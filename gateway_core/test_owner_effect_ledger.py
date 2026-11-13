import concurrent.futures
from contextlib import closing
import sqlite3
import tempfile
import unittest
from pathlib import Path
from owner_effect_ledger import initialize,activate,reserve,finalize,status,Denied

GRANT='a'*64
PAYLOAD='b'*64

def job(n):return f'{n:032x}'
class OwnerEffectLedgerTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory()
  self.addCleanup(self.tmp.cleanup)
  self.db=str(Path(self.tmp.name)/'effect.sqlite')
  initialize(self.db)
  activate(self.db,1,GRANT,3)
 def claim(self,n,rev=1,h=GRANT,max_claims=3):
  return reserve(self.db,job(n),h,rev,max_claims,PAYLOAD,1700000000000+n)
 def test_exact_grant_and_monotonic_consumption(self):
  self.assertEqual(self.claim(1)['state'],'reserved')
  self.assertEqual(finalize(self.db,job(1),'succeeded',1700000000001)['state'],'succeeded')
  self.assertEqual(status(self.db)['active']['claimed'],1)
  with self.assertRaisesRegex(Denied,'effect_replay_blocked'):self.claim(1)
 def test_grant_budget_is_atomic_and_fail_closed(self):
  for n in [1,2,3]:self.claim(n)
  with self.assertRaisesRegex(Denied,'grant_budget_exhausted'):self.claim(4)
  self.assertEqual(status(self.db)['active']['claimed'],3)
 def test_crashed_reserved_job_cannot_be_replayed(self):
  self.claim(1)
  self.assertEqual(status(self.db)['claims'][0]['state'],'reserved')
  with self.assertRaisesRegex(Denied,'effect_replay_blocked'):self.claim(1)
 def test_bad_revision_hash_or_budget_denies(self):
  for args in [(1,2,GRANT,3),(1,1,'b'*64,3),(1,1,GRANT,4)]:
   with self.assertRaisesRegex(Denied,'owner_grant_not_active'):self.claim(*args)
  self.assertEqual(status(self.db)['claims'],[])
 def test_owner_revision_update_revokes_previous(self):
  self.claim(1)
  activate(self.db,2,'c'*64,1)
  with self.assertRaisesRegex(Denied,'owner_grant_not_active'):self.claim(2)
  self.assertEqual(reserve(self.db,job(3),'c'*64,2,1,PAYLOAD,1700000000003)['state'],'reserved')
  with self.assertRaisesRegex(Denied,'stale_activation_revision'):activate(self.db,1,GRANT,3)
 def test_failed_claim_stays_consumed(self):
  self.claim(1)
  finalize(self.db,job(1),'failed',1700000000003)
  with self.assertRaises(Denied):self.claim(1)
  with self.assertRaises(Denied):finalize(self.db,job(1),'succeeded',1700000000004)
 def test_no_auto_recreate_missing_ledger(self):
  Path(self.db).unlink()
  with self.assertRaises(Denied):self.claim(1)
  with self.assertRaises(Denied):status(self.db)
  self.assertFalse(Path(self.db).exists())
 def test_corrupted_count_fails_status(self):
  self.claim(1)
  with closing(sqlite3.connect(self.db)) as conn:
   conn.execute('UPDATE active_grant SET claimed=0')
   conn.commit()
  with self.assertRaisesRegex(Denied,'ledger_history_inconsistent'):status(self.db)
 def test_corrupted_count_denies_reservation_not_only_status(self):
  self.claim(1)
  with closing(sqlite3.connect(self.db)) as conn:
   conn.execute('UPDATE active_grant SET claimed=0')
   conn.commit()
  with self.assertRaisesRegex(Denied,'ledger_history_inconsistent'):self.claim(2)

 def test_concurrent_calls_share_one_claim_budget(self):
  def one(n):
   try:return bool(self.claim(n))
   except Denied:return False
  with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
   wins=list(ex.map(one,range(1,13)))
  self.assertEqual(sum(wins),3)
  self.assertEqual(len(status(self.db)['claims']),3)
 def test_finalize_missing_or_duplicate_denied(self):
  with self.assertRaises(Denied):finalize(self.db,job(1),'failed',1700000000001)
  self.claim(1)
  finalize(self.db,job(1),'succeeded',1700000000002)
  with self.assertRaises(Denied):finalize(self.db,job(1),'succeeded',1700000000003)
 def test_initialize_does_not_overwrite(self):
  with self.assertRaises(Denied):initialize(self.db)
  self.assertEqual(status(self.db)['active']['revision'],1)
if __name__=='__main__':unittest.main()
