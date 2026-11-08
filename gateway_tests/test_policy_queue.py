import hashlib
import hmac
import json
import os
import sqlite3
import tempfile
import unittest

from gateway_core.policy_queue import CapabilityPolicy, Command, Denied, Gateway

KEY = b"nondistributable-owner-test-key-not-a-real-secret!"  # TEST ONLY
FUTURE = "2099-01-01T00:00:00Z"

def grant(enabled=True, ops=None, devices=None, expires=FUTURE):
    return {
        "version": 1, "owner": "local_owner", "expires_utc": expires,
        "capabilities": {"windows_diagnostics": {
            "enabled": enabled,
            "operations": ops if ops is not None else ["snapshot"],
            "devices": devices if devices is not None else ["office_pc"],
        }},
    }

def signed(document):
    raw = json.dumps(document, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, allow_nan=False).encode("ascii")
    sig = hmac.new(KEY, raw, hashlib.sha256).hexdigest()
    return CapabilityPolicy(document, sig, KEY)

class GatewayPolicyTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.gateway = Gateway(os.path.join(self.folder.name, "jobs.sqlite"))
        self.command = Command("job_001", "windows_diagnostics",
                               "snapshot", "office_pc", {"category": "ram"})

    def tearDown(self):
        self.gateway.close()
        self.folder.cleanup()

    def activate_test_policy(self, handler=None):
        self.gateway.policy = signed(grant())
        self.gateway.register_handler("windows_diagnostics", "snapshot",
                                      handler or (lambda payload: {"ok": True, "category": payload["category"]}))

    def test_01_denied_by_default(self):
        with self.assertRaises(Denied):
            self.gateway.submit(self.command)
        self.assertTrue(self.gateway.audit_verified())

    def test_02_wrong_signature_fails_closed(self):
        with self.assertRaises(Denied):
            CapabilityPolicy(grant(), "0" * 64, KEY)

    def test_03_missing_owner_key_fails_closed(self):
        with self.assertRaises(Denied):
            CapabilityPolicy(grant(), "0" * 64, None)

    def test_04_expired_grant_fails_closed(self):
        with self.assertRaises(Denied):
            signed(grant(expires="2020-01-01T00:00:00Z"))

    def test_05_disabled_capability_denied(self):
        self.gateway.policy = signed(grant(enabled=False))
        self.gateway.register_handler("windows_diagnostics", "snapshot", lambda payload: 1)
        with self.assertRaises(Denied):
            self.gateway.submit(self.command)

    def test_06_operation_out_of_scope(self):
        self.activate_test_policy()
        with self.assertRaises(Denied):
            self.gateway.submit(Command("job_002", "windows_diagnostics",
                                        "run_shell", "office_pc", {}))

    def test_07_device_out_of_scope(self):
        self.activate_test_policy()
        with self.assertRaises(Denied):
            self.gateway.submit(Command("job_003", "windows_diagnostics",
                                        "snapshot", "other_device", {}))

    def test_08_missing_trusted_handler(self):
        self.gateway.policy = signed(grant())
        with self.assertRaises(Denied):
            self.gateway.submit(self.command)

    def test_09_durable_offline_wait_and_eventual_completion(self):
        self.activate_test_policy()
        self.assertEqual(self.gateway.submit(self.command), "queued")
        self.assertEqual(self.gateway.execute("job_001", device_online=False), "waiting_for_device")
        self.assertEqual(self.gateway.state("job_001"), "waiting_for_device")
        self.assertEqual(self.gateway.execute("job_001", device_online=True), "succeeded")
        self.assertTrue(self.gateway.audit_verified())

    def test_10_idempotent_replay_denied(self):
        self.activate_test_policy()
        self.gateway.submit(self.command)
        with self.assertRaises(Denied):
            self.gateway.submit(self.command)

    def test_11_second_execution_denied(self):
        self.activate_test_policy()
        self.gateway.submit(self.command)
        self.gateway.execute("job_001", device_online=True)
        with self.assertRaises(Denied):
            self.gateway.execute("job_001", device_online=True)

    def test_12_failing_handler_marked_failed_without_raw_output(self):
        def fail(payload):
            raise RuntimeError("TEST_SECRET_MUST_NOT_BE_LOGGED")
        self.activate_test_policy(fail)
        self.gateway.submit(self.command)
        self.assertEqual(self.gateway.execute("job_001", device_online=True), "failed")
        self.assertNotIn("TEST_SECRET", str(list(self.gateway._db.execute("SELECT event_json FROM audit"))))

    def test_13_detect_audit_tampering(self):
        self.activate_test_policy()
        self.gateway.submit(self.command)
        self.assertTrue(self.gateway.audit_verified())
        self.gateway._db.execute("UPDATE audit SET event_json='tampered' WHERE sequence=1")
        self.gateway._db.commit()
        self.assertFalse(self.gateway.audit_verified())

    def test_14_reject_large_payload(self):
        self.activate_test_policy()
        with self.assertRaises(ValueError):
            self.gateway.submit(Command("job_008", "windows_diagnostics",
                                        "snapshot", "office_pc", {"data": "x" * 5000}))

    def test_15_reject_invalid_identifier(self):
        self.activate_test_policy()
        with self.assertRaises(ValueError):
            self.gateway.submit(Command("invalid;echo", "windows_diagnostics",
                                        "snapshot", "office_pc", {}))

    def test_16_recovery_from_restart(self):
        self.activate_test_policy()
        self.gateway.submit(self.command)
        self.gateway.execute("job_001", device_online=False)
        db_path = os.path.join(self.folder.name, "jobs.sqlite")
        second = Gateway(db_path, self.gateway.policy)
        try:
            second.register_handler("windows_diagnostics", "snapshot", lambda p: {"persisted": True})
            self.assertEqual(second.state("job_001"), "waiting_for_device")
            self.assertEqual(second.execute("job_001", device_online=True), "succeeded")
            self.assertTrue(second.audit_verified())
        finally:
            second.close()

    def test_17_policy_revoked_after_submission(self):
        self.activate_test_policy()
        self.gateway.submit(self.command)
        self.gateway.policy = CapabilityPolicy()
        with self.assertRaises(Denied):
            self.gateway.execute("job_001", device_online=True)

if __name__ == "__main__":
    unittest.main()
