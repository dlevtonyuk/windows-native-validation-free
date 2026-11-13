"""Disposable dual-witness fault-injection lab. Only inert state transitions."""
import base64
import concurrent.futures
import hashlib
import os
import shutil
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from uag.policy import canonical
from dual_witness_fence import SignedSlotWitness,HostHighWaterAnchor,DualWitnessEffectFence,DualWitnessDenied

T=1794514800

def pub(key):return key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)

class DualWitnessTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.owner=Ed25519PrivateKey.generate();self.k={a:Ed25519PrivateKey.generate() for a in ('witness-a','witness-b')}
        self.policy=self.p(1,True);self.revoked=self.p(2,False)
        self.ws={}
        for name in self.k:
            self.ws[name]=SignedSlotWitness(self.root/(name+'.db'),pub(self.owner),self.k[name],name,clock=lambda:T)
            self.ws[name].publish_owner(self.policy,self.sign(self.policy))
        self.anchor=HostHighWaterAnchor(self.root/'host.db',pub(self.owner))
        self.anchor.observe_owner_signed(self.policy,self.sign(self.policy))
        self.fence=self.new_fence()
        self.slot=3600000
        self.cue='aa'*32;self.host='host-a';self.digest=hashlib.sha256(canonical(self.policy)).hexdigest()
    def tearDown(self):
        self.anchor.close()
        for w in self.ws.values():w.close()
        self.tmp.cleanup()
    def p(self,rev,enabled):return{'schema':'uag.distributed-inert-policy.v1','revision':rev,'enabled':enabled}
    def sign(self,p):return self.owner.sign(canonical(p))
    def new_fence(self):return DualWitnessEffectFence(self.ws,{a:pub(k) for a,k in self.k.items()},self.anchor,clock=lambda:T)
    def reserve(self,slot=None):return self.fence.reserve_two(self.slot if slot is None else slot,self.cue,1,self.host,self.digest)
    def authorize(self,r,slot=None):return self.fence.authorize_inert_effect(r,self.slot if slot is None else slot,self.cue,1,self.host,self.digest)
    def snapshot(self,path):
        f=self.root/(Path(path).stem+'.snapshot.db')
        if Path(path).resolve()==f.resolve():raise AssertionError('bad_backup')
        conn=sqlite3.connect(path)
        with sqlite3.connect(f) as dest:conn.backup(dest)
        conn.close();return f
    def restore_w(self,name,backup):
        w=self.ws[name];w.close();path=self.root/(name+'.db')
        for ext in ('','-wal','-shm'):
            f=Path(str(path)+ext)
            if f.exists():f.unlink()
        shutil.copy2(backup,path)
        self.ws[name]=SignedSlotWitness(path,pub(self.owner),self.k[name],name,clock=lambda:T)
        self.fence=self.new_fence()
    def update(self,name,policy):self.ws[name].publish_owner(policy,self.sign(policy))

    def test_two_distinct_pinned_keys_are_required(self):
        with self.assertRaises(DualWitnessDenied):DualWitnessEffectFence(self.ws,{'witness-a':pub(self.k['witness-a']),'witness-b':pub(self.k['witness-a'])},self.anchor)
    def test_both_witnesses_required(self):
        with self.assertRaises(DualWitnessDenied):DualWitnessEffectFence({'witness-a':self.ws['witness-a']},{'witness-a':pub(self.k['witness-a'])},self.anchor)
    def test_one_authorized_inert_effect(self):
        r=self.reserve();self.assertTrue(self.authorize(r));self.assertEqual(len(self.ws['witness-a'].conn.execute('SELECT * FROM effect_auth').fetchall()),1)
    def test_second_attempt_same_receipts_denied(self):
        r=self.reserve();self.assertTrue(self.authorize(r))
        with self.assertRaises(DualWitnessDenied):self.authorize(r)
    def test_second_reservation_same_slot_denied(self):
        self.reserve()
        with self.assertRaises(DualWitnessDenied):self.reserve()
    def test_first_witness_revoked_blocks_reserved_effect(self):
        r=self.reserve();self.update('witness-a',self.revoked)
        with self.assertRaises(DualWitnessDenied):self.authorize(r)
    def test_second_witness_revoked_blocks_reserved_effect(self):
        r=self.reserve();self.update('witness-b',self.revoked)
        with self.assertRaises(DualWitnessDenied):self.authorize(r)
    def test_first_witness_rollback_second_still_revoked_blocks_old_grant(self):
        r=self.reserve();snap=self.snapshot(self.ws['witness-a'].path)
        self.update('witness-a',self.revoked);self.update('witness-b',self.revoked)
        self.restore_w('witness-a',snap)
        self.assertEqual(self.ws['witness-a'].current()['revision'],1)
        with self.assertRaises(DualWitnessDenied):self.authorize(r)
    def test_second_witness_rollback_first_still_revoked_blocks_old_grant(self):
        r=self.reserve();snap=self.snapshot(self.ws['witness-b'].path)
        self.update('witness-a',self.revoked);self.update('witness-b',self.revoked)
        self.restore_w('witness-b',snap)
        with self.assertRaises(DualWitnessDenied):self.authorize(r)
    def test_both_witnesses_rollback_but_host_saw_revocation(self):
        snaps={a:self.snapshot(w.path) for a,w in self.ws.items()}
        for name in self.ws:self.update(name,self.revoked)
        self.anchor.observe_owner_signed(self.revoked,self.sign(self.revoked))
        for name in list(self.ws):self.restore_w(name,snaps[name])
        r=self.reserve(slot=self.slot+3600000)
        with self.assertRaisesRegex(DualWitnessDenied,'host_detected_rollback_or_fork'):
            self.authorize(r,slot=self.slot+3600000)
    def test_host_anchor_rollback_but_two_witness_consumptions_survive(self):
        snap=self.snapshot(self.anchor.path)
        r=self.reserve();self.assertTrue(self.authorize(r))
        self.anchor.close()
        for ext in ('','-wal','-shm'):
            f=Path(str(self.root/'host.db')+ext)
            if f.exists():f.unlink()
        shutil.copy2(snap,self.root/'host.db')
        self.anchor=HostHighWaterAnchor(self.root/'host.db',pub(self.owner));self.fence=self.new_fence()
        with self.assertRaises(DualWitnessDenied):self.authorize(r)
    def test_both_witnesses_survive_coordinator_database_restoration(self):
        r=self.reserve();self.assertTrue(self.authorize(r))
        with self.assertRaises(DualWitnessDenied):self.reserve()
    def test_witness_a_unavailable_fails_closed(self):
        r=self.reserve();self.ws['witness-a'].available=False
        with self.assertRaises(DualWitnessDenied):self.authorize(r)
    def test_witness_b_unavailable_fails_closed(self):
        r=self.reserve();self.ws['witness-b'].available=False
        with self.assertRaises(DualWitnessDenied):self.authorize(r)
    def test_witness_a_reserves_then_b_lost_response_quarantines(self):
        self.ws['witness-b'].available=False
        with self.assertRaisesRegex(DualWitnessDenied,'quarantine'):self.reserve()
        self.assertIsNotNone(self.ws['witness-a'].slot(self.slot))
        self.ws['witness-b'].available=True
        with self.assertRaises(DualWitnessDenied):self.reserve()
    def test_witness_a_effect_issued_then_b_fails_cannot_replay(self):
        r=self.reserve();self.ws['witness-b'].available=False
        with self.assertRaises(DualWitnessDenied):self.authorize(r)
        self.assertEqual(self.ws['witness-a'].conn.execute('SELECT COUNT(*) FROM effect_auth').fetchone()[0],1)
        self.ws['witness-b'].available=True
        with self.assertRaises(DualWitnessDenied):self.authorize(r)
    def test_nonce_replay_response_denied(self):
        r=self.reserve();w=self.ws['witness-a'];old=w.authorize_once
        def forged(nonce,*args):return old('b'*48,*args)
        w.authorize_once=forged
        try:
            with self.assertRaises(DualWitnessDenied):self.authorize(r)
        finally:w.authorize_once=old
    def test_one_witness_clock_stale_denied(self):
        r=self.reserve();self.ws['witness-b'].clock=lambda:T-60
        with self.assertRaises(DualWitnessDenied):self.authorize(r)
    def test_one_witness_clock_future_denied(self):
        r=self.reserve();self.ws['witness-b'].clock=lambda:T+60
        with self.assertRaises(DualWitnessDenied):self.authorize(r)
    def test_forced_signature_forgery_denied(self):
        r=self.reserve();r['witness-a']['signature_b64']=base64.b64encode(Ed25519PrivateKey.generate().sign(canonical(r['witness-a']['payload']))).decode()
        with self.assertRaises(DualWitnessDenied):self.authorize(r)
    def test_cross_witness_signature_swap_denied(self):
        r=self.reserve();r['witness-a']['signature_b64'],r['witness-b']['signature_b64']=r['witness-b']['signature_b64'],r['witness-a']['signature_b64']
        with self.assertRaises(DualWitnessDenied):self.authorize(r)
    def test_extra_reservation_field_denied(self):
        r=self.reserve();r['witness-a']['payload']['shell']='FORBIDDEN'
        with self.assertRaises(DualWitnessDenied):self.authorize(r)
    def test_invalid_claim_host_denied(self):
        r=self.reserve()
        with self.assertRaises(DualWitnessDenied):self.fence.authorize_inert_effect(r,self.slot,self.cue,1,'host-b',self.digest)
    def test_wrong_cue_digest_denied(self):
        r=self.reserve()
        with self.assertRaises(DualWitnessDenied):self.fence.authorize_inert_effect(r,self.slot,'bb'*32,1,self.host,self.digest)
    def test_wrong_slot_denied(self):
        r=self.reserve()
        with self.assertRaises(DualWitnessDenied):self.authorize(r,self.slot+3600000)
    def test_persisted_host_anchor_rejects_old_owner_update(self):
        self.anchor.observe_owner_signed(self.revoked,self.sign(self.revoked))
        with self.assertRaises(DualWitnessDenied):self.anchor.observe_owner_signed(self.policy,self.sign(self.policy))
    def test_host_anchor_rejects_forged_owner_update(self):
        with self.assertRaises(DualWitnessDenied):self.anchor.observe_owner_signed(self.revoked,Ed25519PrivateKey.generate().sign(canonical(self.revoked)))
    def test_host_anchor_rejects_same_revision_fork(self):
        fork=self.p(1,False)
        with self.assertRaises(DualWitnessDenied):self.anchor.observe_owner_signed(fork,self.sign(fork))
    def test_host_anchor_floor_survives_restart(self):
        self.anchor.observe_owner_signed(self.revoked,self.sign(self.revoked))
        self.anchor.close();self.anchor=HostHighWaterAnchor(self.root/'host.db',pub(self.owner));self.fence=self.new_fence()
        self.assertEqual(self.anchor.floor()[0],2)
    def test_effect_reservation_survives_witness_restart(self):
        r=self.reserve();self.assertTrue(self.authorize(r))
        for name in list(self.ws):
            self.ws[name].close();self.ws[name]=SignedSlotWitness(self.root/(name+'.db'),pub(self.owner),self.k[name],name,clock=lambda:T)
        self.fence=self.new_fence()
        with self.assertRaises(DualWitnessDenied):self.authorize(r)
    def test_two_concurrent_receivers_one_effect_only(self):
        r=self.reserve();barrier=threading.Barrier(2)
        def work():
            barrier.wait(timeout=4)
            try:self.authorize(r);return'allowed'
            except DualWitnessDenied:return'denied'
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
            a=ex.submit(work);b=ex.submit(work);states=[a.result(timeout=10),b.result(timeout=10)]
        self.assertCountEqual(states,['allowed','denied'])
    def test_different_claims_not_released_when_one_witness_replaying(self):
        r=self.reserve();self.assertTrue(self.authorize(r));second=self.slot+3600000
        r2=self.reserve(slot=second);self.assertTrue(self.authorize(r2,slot=second))
        self.assertEqual(self.anchor.conn.execute('SELECT COUNT(*) FROM consumed').fetchone()[0],2)
    def test_witness_policy_revocation_immediately_before_second_effect_issuance(self):
        r=self.reserve();w=self.ws['witness-b'];original=w.authorize_once
        def revoke_then(*args):w.publish_owner(self.revoked,self.sign(self.revoked));return original(*args)
        w.authorize_once=revoke_then
        try:
            with self.assertRaises(DualWitnessDenied):self.authorize(r)
        finally:w.authorize_once=original
    def test_bad_host_anchor_id_rejects_same_revision_inconsistent_hash(self):
        with self.assertRaises(DualWitnessDenied):self.anchor.consume(1,'ee'*32,self.slot,'ab'*32)

if __name__=='__main__':unittest.main(verbosity=2)
