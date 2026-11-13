"""Cross-platform tests for bounded live-receipt continuity interpretation."""
import unittest
from cloud_host.synthetic_cron.verify_continuity import (
    check_snapshot, FIRST_LIVE_SLOT_MS, SLOT_MS
)

FIRST = FIRST_LIVE_SLOT_MS


def item(i, delta=54_375, kind="synthetic_heartbeat"):
    t = FIRST + i * SLOT_MS
    return {"slot_ms": t, "kind": kind, "scheduled_at_ms": t + delta}


def sample(now_delta_ms, *items):
    return {"observed_ms": FIRST + now_delta_ms,
            "first_expected_slot_ms": FIRST, "rows": list(items)}


class ContinuityWitnessTests(unittest.TestCase):
    def test_before_first_slot_no_false_success(self):
        result = check_snapshot(sample(-1000))
        self.assertEqual(result["status"], "PENDING")
        self.assertEqual(result["unique_receipt_slots"], 0)

    def test_first_real_hour_consistent_but_not_24h(self):
        result = check_snapshot(sample(10 * 60_000, item(0)))
        self.assertEqual(result["status"], "CONSISTENT")
        self.assertEqual(result["expected_due_slots"], 0)
        self.assertFalse(result["continuous_24h_window"])
        self.assertEqual(result["provenance"], "snapshot_only_unverified_origin")

    def test_no_data_after_grace_fails(self):
        result = check_snapshot(sample(16 * 60_000))
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["missing_slots_ms"], [FIRST])

    def test_new_hour_not_due_in_grace(self):
        result = check_snapshot(sample(SLOT_MS + 10 * 60_000, item(0)))
        self.assertEqual(result["status"], "CONSISTENT")
        self.assertEqual(result["expected_due_slots"], 1)

    def test_lost_hour_detected(self):
        result = check_snapshot(sample(3 * SLOT_MS + 20 * 60_000, item(0), item(2), item(3)))
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["missing_slots_ms"], [FIRST + SLOT_MS])

    def test_duplicate_not_described_as_reliable(self):
        result = check_snapshot(sample(2 * SLOT_MS + 30 * 60_000, item(0), item(1), item(1), item(2)))
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["duplicate_slots_ms"], [FIRST + SLOT_MS])

    def test_wrong_kind_fails(self):
        result = check_snapshot(sample(20 * 60_000, item(0, kind="business_job")))
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["invalid_rows"][0]["reason"], "unexpected_kind")

    def test_bad_scheduled_timestamp_fails(self):
        bad = item(0, delta=SLOT_MS)
        self.assertEqual(check_snapshot(sample(2 * SLOT_MS, bad))["status"], "FAILED")

    def test_malformed_and_boolean_clocks_denied(self):
        with self.assertRaisesRegex(ValueError, "invalid_clock_or_first_slot"):
            check_snapshot({"observed_ms": True, "first_expected_slot_ms": FIRST, "rows": []})
        with self.assertRaisesRegex(ValueError, "unexpected_snapshot_schema"):
            check_snapshot({"observed_ms": FIRST, "first_expected_slot_ms": FIRST, "rows": [], "token": "secret"})
        with self.assertRaisesRegex(ValueError, "too_many_or_invalid_rows"):
            check_snapshot(sample(20 * 60_000, *([item(0)] * 201)))

    def test_24_and_48_hour_proofs_require_full_continuous_window(self):
        rows = [item(i) for i in range(49)]
        r24 = check_snapshot(sample(24 * SLOT_MS + 20 * 60_000, *rows[:25]))
        self.assertEqual(r24["status"], "CONSISTENT")
        self.assertTrue(r24["continuous_24h_window"])
        self.assertFalse(r24["continuous_48h_window"])
        r48 = check_snapshot(sample(48 * SLOT_MS + 20 * 60_000, *rows))
        self.assertTrue(r48["continuous_48h_window"])
        bad = check_snapshot(sample(48 * SLOT_MS + 20 * 60_000, *(rows[:20] + rows[21:])))
        self.assertEqual(bad["status"], "FAILED")
        self.assertFalse(bad["continuous_48h_window"])

    def test_reject_stale_long_ago_or_future_clock(self):
        with self.assertRaisesRegex(ValueError, "outside_finite"):
            check_snapshot(sample(91 * SLOT_MS))
        with self.assertRaisesRegex(ValueError, "observation_clock_before"):
            check_snapshot(sample(-2 * SLOT_MS))


if __name__ == "__main__":
    unittest.main()
