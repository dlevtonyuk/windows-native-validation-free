import base64
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_dual_witness_fence import DualWitnessTests, pub, T
from dual_witness_fence import DualWitnessDenied
from final_quorum_fence import FinalQuorumFence
from uag.policy import canonical

class FinalQuorumTests(DualWitnessTests):
    def setUp(self):
        super().setUp()
        self.fence=self.new_fence()
    def new_fence(self):
        return FinalQuorumFence(self.ws,{k:pub(p) for k,p in self.k.items()},self.anchor,clock=lambda:T)

    def test_revocation_a_between_a_and_b_issuance_denied(self):
        r=self.reserve(); w=self.ws['witness-b']; orig=w.authorize_once
        def update_before_b(*args):
            self.update('witness-a',self.revoked)
            return orig(*args)
        w.authorize_once=update_before_b
        with self.assertRaisesRegex(DualWitnessDenied,'fresh_quorum_denied_quarantine'):
            self.authorize(r)
        self.assertIsNotNone(self.anchor.consumed(self.slot))

    def test_revocation_b_after_b_issuance_denied(self):
        r=self.reserve();w=self.ws['witness-b'];orig=w.authorize_once
        def update_after_b(*args):
            result=orig(*args);self.update('witness-b',self.revoked);return result
        w.authorize_once=update_after_b
        with self.assertRaisesRegex(DualWitnessDenied,'fresh_quorum_denied_quarantine'):
            self.authorize(r)
        self.assertIsNotNone(self.anchor.consumed(self.slot))

    def test_both_quorum_current_permits_inert_effect(self):
        self.assertTrue(self.authorize(self.reserve()))

    def test_final_a_witness_outage_denies(self):
        r=self.reserve();a=self.ws['witness-a'];original=a.authorize_once
        def goes_offline(*args):
            result=original(*args);a.available=False;return result
        a.authorize_once=goes_offline
        with self.assertRaises(DualWitnessDenied):self.authorize(r)

    def test_final_b_witness_outage_denies(self):
        r=self.reserve();b=self.ws['witness-b'];original=b.authorize_once
        def goes_offline(*args):
            result=original(*args);b.available=False;return result
        b.authorize_once=goes_offline
        with self.assertRaises(DualWitnessDenied):self.authorize(r)

    def test_final_a_status_signed_with_wrong_key_denies(self):
        r=self.reserve();a=self.ws['witness-a'];original=a.attest_current
        def forged(nonce):
            response=original(nonce)
            response['signature_b64']=base64.b64encode(Ed25519PrivateKey.generate().sign(canonical(response['payload']))).decode()
            return response
        a.attest_current=forged
        with self.assertRaises(DualWitnessDenied):self.authorize(r)

    def test_final_b_status_signed_with_wrong_key_denies(self):
        r=self.reserve();b=self.ws['witness-b'];original=b.attest_current
        def forged(nonce):
            response=original(nonce)
            response['signature_b64']=base64.b64encode(Ed25519PrivateKey.generate().sign(canonical(response['payload']))).decode()
            return response
        b.attest_current=forged
        with self.assertRaises(DualWitnessDenied):self.authorize(r)

    def test_replayed_nonce_denied(self):
        r=self.reserve();a=self.ws['witness-a'];original=a.attest_current
        a.attest_current=lambda nonce: original('a'*48)
        with self.assertRaises(DualWitnessDenied):self.authorize(r)

    def test_stale_final_attestation_denied(self):
        r=self.reserve();a=self.ws['witness-a'];original=a.attest_current
        def stale(nonce):
            a.clock=lambda:T-30
            return original(nonce)
        a.attest_current=stale
        with self.assertRaises(DualWitnessDenied):self.authorize(r)

    def test_unknown_extra_final_status_field_denied(self):
        r=self.reserve();a=self.ws['witness-a'];original=a.attest_current
        def extra(nonce):
            v=original(nonce);v['payload']['command']='rm -rf';return v
        a.attest_current=extra
        with self.assertRaises(DualWitnessDenied):self.authorize(r)

    def test_final_quorum_loss_forfeits_slot_no_automatic_replay(self):
        r=self.reserve();a=self.ws['witness-a'];old=a.attest_current
        a.attest_current=lambda nonce: (_ for _ in ()).throw(ConnectionError('packet lost'))
        with self.assertRaises(DualWitnessDenied):self.authorize(r)
        a.attest_current=old
        with self.assertRaises(DualWitnessDenied):self.authorize(r)

    def test_owner_revocation_seen_host_anchor_blocks(self):
        r=self.reserve(); self.anchor.observe_owner_signed(self.revoked,self.sign(self.revoked))
        with self.assertRaises(DualWitnessDenied):self.authorize(r)

if __name__=='__main__':unittest.main(verbosity=2)
