"""Fictional-only SQLite/D1 provider-job continuation acceptance tests.

No real API credentials, provider data, Cloudflare writes, or other effects.
"""
from pathlib import Path
import sqlite3
import tempfile
import unittest

SCHEMA = Path(__file__).with_name('durable_provider.sql').read_text(encoding='utf-8')
KEY = 'fictional:1000:2000'

def init(path):
    db = sqlite3.connect(path)
    db.execute('PRAGMA foreign_keys=ON')
    db.executescript(SCHEMA)
    return db

def seed(db):
    db.execute('INSERT INTO uag_provider_runs(period_key,start_unix,end_unix,updated_ms) VALUES(?,?,?,?)', (KEY, 1000, 2000, 1))
    db.commit()

def claim(db, now):
    q = '''UPDATE uag_provider_runs SET lease_until_ms=?,attempt_count=attempt_count+1,
        revision=revision+1,updated_ms=? WHERE period_key=? AND
        phase IN ('new','poll','download') AND next_due_ms<=? AND
        (lease_until_ms=0 OR lease_until_ms<?) AND attempt_count<12'''
    result = db.execute(q,(now+300000,now,KEY,now,now))
    db.commit()
    return result.rowcount

def change(db, sql, args):
    try:
        db.execute(sql,args)
        db.commit()
    except sqlite3.IntegrityError:
        db.rollback()
        raise

def snapshot(db):
    return db.execute('SELECT phase,zoho_job_id,expiry_ms,revision,lease_until_ms,result_sha256,attempt_count FROM uag_provider_runs WHERE period_key=?',(KEY,)).fetchone()

class ProviderDurability(unittest.TestCase):
    def test_real_disk_restart_1001_1002_1004_review_path(self):
        with tempfile.TemporaryDirectory() as d:
            f=str(Path(d)/'probe.sqlite')
            db=init(f); seed(db)
            self.assertEqual(claim(db,100),1)
            self.assertEqual(claim(db,110),0)
            change(db,'UPDATE uag_provider_runs SET phase=\'poll\',zoho_job_id=?,lease_until_ms=0,revision=revision+1,updated_ms=? WHERE period_key=?',('999',120,KEY))
            db.close()
            # Separate invocation/process opens the same durable job state.
            db=init(f); self.assertEqual(snapshot(db)[:2],('poll','999'))
            self.assertEqual(claim(db,200),1)
            # 1001: job not yet initiated; no retry duplicate creation.
            change(db,'UPDATE uag_provider_runs SET next_due_ms=?,lease_until_ms=0,revision=revision+1,updated_ms=? WHERE period_key=?',(230,210,KEY))
            self.assertEqual(claim(db,220),0)
            self.assertEqual(claim(db,230),1)
            # 1002: still running; state and original job ID preserved.
            change(db,'UPDATE uag_provider_runs SET next_due_ms=?,lease_until_ms=0,revision=revision+1,updated_ms=? WHERE period_key=?',(270,240,KEY))
            db.close()
            db=init(f)
            self.assertEqual(claim(db,280),1)
            change(db,'UPDATE uag_provider_runs SET phase=\'download\',expiry_ms=?,lease_until_ms=0,revision=revision+1,updated_ms=? WHERE period_key=?',(999999,290,KEY))
            self.assertEqual(snapshot(db)[:3],('download','999',999999))
            self.assertEqual(claim(db,300),1)
            # Full input coverage is required: a submitted-card gap gets review_required, never complete.
            change(db,'UPDATE uag_provider_runs SET phase=\'review_required\',result_sha256=?,aggregate_json=?,lease_until_ms=0,revision=revision+1,updated_ms=? WHERE period_key=?',('a'*64,'{"missing_by_status":{"submitted":1}}',310,KEY))
            self.assertEqual(snapshot(db)[0],'review_required')
            events=[x[0] for x in db.execute('SELECT event_kind FROM uag_provider_events ORDER BY event_id')]
            self.assertEqual(events,['claimed','export_started','claimed','deferred','claimed','deferred','claimed','export_ready','claimed','review_required'])
            self.assertEqual(claim(db,320),0)
            db.close()

    def test_invalid_transition_rejected_and_no_audit(self):
        db=init(':memory:');seed(db)
        self.assertEqual(claim(db,100),1)
        before=snapshot(db)
        with self.assertRaises(sqlite3.IntegrityError):
            change(db,'UPDATE uag_provider_runs SET phase=\'complete\',result_sha256=?,lease_until_ms=0,revision=revision+1,updated_ms=? WHERE period_key=?',('b'*64,110,KEY))
        self.assertEqual(snapshot(db),before)
        self.assertEqual(db.execute('SELECT COUNT(*) FROM uag_provider_events').fetchone()[0],1)
        db.close()

    def test_audit_insertion_failure_rollback(self):
        db=init(':memory:');seed(db)
        self.assertEqual(claim(db,100),1)
        db.executescript('''CREATE TRIGGER broken_audit BEFORE INSERT ON uag_provider_events
            WHEN NEW.event_kind='export_started' BEGIN SELECT RAISE(ABORT,'synthetic_audit_failure'); END;''')
        before=snapshot(db)
        with self.assertRaises(sqlite3.IntegrityError):
            change(db,'UPDATE uag_provider_runs SET phase=\'poll\',zoho_job_id=?,lease_until_ms=0,revision=revision+1,updated_ms=? WHERE period_key=?',('999',110,KEY))
        self.assertEqual(snapshot(db),before)
        self.assertEqual(db.execute('SELECT COUNT(*) FROM uag_provider_events').fetchone()[0],1)
        db.close()

    def test_lease_expiry_recovery_and_terminal_deadletter(self):
        db=init(':memory:');seed(db)
        self.assertEqual(claim(db,100),1)
        self.assertEqual(claim(db,150),0)
        self.assertEqual(claim(db,300101),1)
        change(db,'UPDATE uag_provider_runs SET phase=\'deadletter\',last_error_code=?,lease_until_ms=0,revision=revision+1,updated_ms=? WHERE period_key=?',('unknown_export_outcome',300120,KEY))
        self.assertEqual(snapshot(db)[0],'deadletter')
        self.assertEqual(claim(db,300200),0)
        db.close()

    def test_omitting_revision_cannot_change_state_or_claim(self):
        db=init(':memory:');seed(db)
        with self.assertRaises(sqlite3.IntegrityError):
            change(db,"UPDATE uag_provider_runs SET phase='deadletter',last_error_code='bypass' WHERE period_key=?",(KEY,))
        with self.assertRaises(sqlite3.IntegrityError):
            change(db,'UPDATE uag_provider_runs SET lease_until_ms=123456 WHERE period_key=?',(KEY,))
        self.assertEqual(snapshot(db)[0],'new')
        self.assertEqual(db.execute('SELECT COUNT(*) FROM uag_provider_events').fetchone()[0],0)
        db.close()

    def test_immutable_period_and_revision_skip_blocked(self):
        db=init(':memory:');seed(db)
        self.assertEqual(claim(db,100),1)
        with self.assertRaises(sqlite3.IntegrityError):
            change(db,'UPDATE uag_provider_runs SET end_unix=3000,lease_until_ms=0,revision=revision+1,updated_ms=110 WHERE period_key=?',(KEY,))
        with self.assertRaises(sqlite3.IntegrityError):
            change(db,'UPDATE uag_provider_runs SET lease_until_ms=0,revision=revision+2,updated_ms=110 WHERE period_key=?',(KEY,))
        self.assertEqual(snapshot(db)[3],1)
        db.close()

if __name__=='__main__':unittest.main()
