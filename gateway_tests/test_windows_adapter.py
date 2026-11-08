import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest

from gateway_core.policy_queue import CapabilityPolicy, Command, Gateway
from gateway_core.windows_adapter import WindowsPressureAdapter

SCRIPT = Path(__file__).resolve().parent.parent / "tests" / "ReadOnly-Pressure.ps1"
KEY = b"synthetic-windows-adapter-owner-key-ONLY-FOR-TESTS"

def test_grant():
    d = {"version": 1, "owner": "local_owner", "expires_utc": "2099-01-01T00:00:00Z",
         "capabilities": {"windows_diagnostics": {"enabled": True,
             "operations": ["snapshot"], "devices": ["ephemeral_vm"]}}}
    raw = json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return CapabilityPolicy(d, hmac.new(KEY, raw, hashlib.sha256).hexdigest(), KEY)

class ReadOnlyWindowsAdapterTests(unittest.TestCase):
    def test_reject_non_windows(self):
        if os.name == "nt":
            self.skipTest("Windows integration tests follow")
        with self.assertRaises(RuntimeError):
            WindowsPressureAdapter(str(SCRIPT), "0" * 64)

    @unittest.skipUnless(os.name == "nt", "native Windows only")
    def test_01_reject_wrong_pinned_hash(self):
        with self.assertRaises(PermissionError):
            WindowsPressureAdapter(str(SCRIPT), "0" * 64)

    @unittest.skipUnless(os.name == "nt", "native Windows only")
    def test_02_reject_unexpected_request_arguments(self):
        hashvalue = hashlib.sha256(SCRIPT.read_bytes()).hexdigest()
        adapter = WindowsPressureAdapter(str(SCRIPT), hashvalue)
        with self.assertRaises(ValueError):
            adapter.snapshot({"script": "remove-something"})

    @unittest.skipUnless(os.name == "nt", "native Windows only")
    def test_03_detect_script_change_after_registration(self):
        with tempfile.TemporaryDirectory() as d:
            trusted = Path(d) / "ReadOnly-Pressure.ps1"
            shutil.copyfile(SCRIPT, trusted)
            adapter = WindowsPressureAdapter(str(trusted),
                                             hashlib.sha256(trusted.read_bytes()).hexdigest())
            trusted.write_bytes(trusted.read_bytes() + b"\n# test edit")
            with self.assertRaises(PermissionError):
                adapter.snapshot({})

    @unittest.skipUnless(os.name == "nt", "native Windows only")
    def test_04_real_readonly_snapshot_through_gateway(self):
        with tempfile.TemporaryDirectory() as d:
            adapter = WindowsPressureAdapter(str(SCRIPT),
                                             hashlib.sha256(SCRIPT.read_bytes()).hexdigest(),
                                             timeout_seconds=45)
            db_path = str(Path(d) / "gateway.db")
            gateway = Gateway(db_path, test_grant())
            try:
                gateway.register_handler("windows_diagnostics", "snapshot", adapter.snapshot)
                command = Command("windows_snapshot_001", "windows_diagnostics",
                                  "snapshot", "ephemeral_vm", {})
                self.assertEqual(gateway.submit(command), "queued")
                self.assertEqual(gateway.execute(command.job_id, device_online=True), "succeeded")
                row = gateway._db.execute("SELECT result_json FROM jobs WHERE job_id=?",
                                          (command.job_id,)).fetchone()
                result = json.loads(row[0])
                self.assertEqual(result["status"], "read_only")
                self.assertGreaterEqual(result["ram_used_percent"], 0)
                self.assertLessEqual(result["ram_used_percent"], 100)
                self.assertGreater(result["process_count"], 0)
                self.assertNotIn("top_handles", result)
                self.assertTrue(gateway.audit_verified())
                print("GATEWAY_WINDOWS_READONLY_ADAPTER_PASSED")
            finally:
                gateway.close()

if __name__ == "__main__":
    unittest.main()
