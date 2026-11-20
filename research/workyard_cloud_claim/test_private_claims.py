"""Synthetic-only tests. Never reads credentials or performs network I/O."""
import base64
import json
import unittest
from private_claims import Held,Intent,OwnerPrivateGithubLedger,_blob_hash,attempt_approval

ORG=101
CARD=123
REV=1790000000
GRANT="a"*64

class FakeGithub:
    def __init__(self):
        self.files={}
        self.put_count=0
        self.fail_readback=False
        self.unknown_put=False
        self.tamper_content=False

    def __call__(self,method,path,body):
        if method=="PUT":
            self.put_count+=1
            if self.unknown_put:
                raise TimeoutError("outcome unknown")
            if path in self.files:
                return 422,{"message":"exists"}
            raw=base64.b64decode(body["content"])
            sha=_blob_hash(raw)
            self.files[path]=(raw,sha)
            return 201,{"content":{"sha":sha},"commit":{"sha":"e"*40}}
        if method=="GET":
            path=path.removesuffix("?ref=main")
            if self.fail_readback:
                raise TimeoutError("read unavailable")
            if path not in self.files:
                return 404,{"message":"missing"}
            raw,sha=self.files[path]
            if self.tamper_content:raw=b"bad"
            return 200,{"sha":sha,"content":base64.b64encode(raw).decode(),"encoding":"base64"}
        raise AssertionError("unpermitted operation")

class FakeGate:
    def __init__(self):self.calls=0;self.fail=False;self.status="submitted";self.revision=REV
    def preflight(self,card):return {"id":card,"status":self.status,"updated_at_unix":self.revision}
    def approve(self,card,rev):
        self.calls+=1
        if self.fail:raise TimeoutError("provider ambiguous")
        return {"verified_approved":True,"time_card_id":card,"status":"approved"}

class TestOwnerPrivateLedger(unittest.TestCase):
    def setUp(self):
        self.github=FakeGithub()
        self.store=OwnerPrivateGithubLedger("owner/owner-private", "main",self.github)
        self.gate=FakeGate()
        self.intent=Intent(ORG,CARD,REV,GRANT)
    def test_valid_single_approval(self):
        v=attempt_approval(gate=self.gate,ledger=self.store,intent=self.intent)
        self.assertTrue(v["verified_approved"]);self.assertEqual(self.gate.calls,1)
        self.assertEqual(len(self.github.files),2)
    def test_replay_across_new_adapter_instance_denied(self):
        attempt_approval(gate=self.gate,ledger=self.store,intent=self.intent)
        another=OwnerPrivateGithubLedger("owner/owner-private","main",self.github)
        with self.assertRaises(Held):attempt_approval(gate=self.gate,ledger=another,intent=self.intent)
        self.assertEqual(self.gate.calls,1)
    def test_unverified_reservation_blocks_provider(self):
        self.github.fail_readback=True
        with self.assertRaises(Held):attempt_approval(gate=self.gate,ledger=self.store,intent=self.intent)
        self.assertEqual(self.gate.calls,0)
        self.assertEqual(len(self.github.files),1)
    def test_unknown_reservation_blocks_provider(self):
        self.github.unknown_put=True
        with self.assertRaises(Held):attempt_approval(gate=self.gate,ledger=self.store,intent=self.intent)
        self.assertEqual(self.gate.calls,0)
    def test_content_mismatch_blocks_provider(self):
        self.github.tamper_content=True
        with self.assertRaises(Held):attempt_approval(gate=self.gate,ledger=self.store,intent=self.intent)
        self.assertEqual(self.gate.calls,0)
    def test_provider_timeout_consumes_claim(self):
        self.gate.fail=True
        with self.assertRaises(Held):attempt_approval(gate=self.gate,ledger=self.store,intent=self.intent)
        self.assertEqual(self.gate.calls,1)
        self.gate.fail=False
        with self.assertRaises(Held):attempt_approval(gate=self.gate,ledger=self.store,intent=self.intent)
        self.assertEqual(self.gate.calls,1)
    def test_new_revision_cannot_reuse_same_claimed_card(self):
        attempt_approval(gate=self.gate,ledger=self.store,intent=self.intent)
        newer=Intent(ORG,CARD,REV+2,GRANT)
        self.gate.revision=REV+2
        with self.assertRaises(Held):attempt_approval(gate=self.gate,ledger=self.store,intent=newer)
        self.assertEqual(self.gate.calls,1)
    def test_status_changed_blocks_before_ledger(self):
        self.gate.status="approved"
        with self.assertRaises(Held):attempt_approval(gate=self.gate,ledger=self.store,intent=self.intent)
        self.assertEqual(self.github.put_count,0)
    def test_stale_revision_blocks_before_ledger(self):
        self.gate.revision+=1
        with self.assertRaises(Held):attempt_approval(gate=self.gate,ledger=self.store,intent=self.intent)
        self.assertEqual(self.github.put_count,0)
    def test_bad_grant_hash_fails(self):
        with self.assertRaises(Held):Intent(ORG,CARD,REV,"bad").bytes()
    def test_repo_or_branch_protected(self):
        with self.assertRaises(Held):OwnerPrivateGithubLedger("not valid","main",self.github)
        with self.assertRaises(Held):OwnerPrivateGithubLedger("owner/repo","dev",self.github)
        with self.assertRaises(Held):OwnerPrivateGithubLedger("owner/repo","main",None)
    def test_receipt_unverified_means_no_completion_claim(self):
        class FailingReceipt(OwnerPrivateGithubLedger):
            def receipt(self, intent, outcome):
                raise Held("receipt_not_confirmed")
        store=FailingReceipt("owner/owner-private", "main",self.github)
        with self.assertRaises(Held) as ctx:
            attempt_approval(gate=self.gate,ledger=store,intent=self.intent)
        self.assertIn("receipt_unconfirmed",str(ctx.exception))
        self.assertEqual(self.gate.calls,1)
        with self.assertRaises(Held):
            attempt_approval(gate=self.gate,ledger=store,intent=self.intent)
        self.assertEqual(self.gate.calls,1)
    def test_receipt_has_independent_readback(self):
        attempt_approval(gate=self.gate,ledger=self.store,intent=self.intent)
        self.assertEqual(self.github.put_count,2)
        self.assertEqual(len(self.github.files),2)
    def test_real_network_absent(self):
        import inspect,private_claims
        source=inspect.getsource(private_claims)
        self.assertNotIn("urllib.request",source)
        self.assertNotIn("requests.",source)
        self.assertNotIn("api.workyard.com",source)
        self.assertNotIn("WORKYARD_API_TOKEN",source)

if __name__=="__main__":unittest.main()