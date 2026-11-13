"""Offline, deterministic D1 synthetic Cron continuity checker.

This module NEVER calls Cloudflare or other networks. Its input is an *untrusted
snapshot*. A PASS establishes consistency of supplied rows, not evidence that
an actual cloud invocation occurred; the source/provenance must be verified
separately using the official Cloudflare API.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

SLOT_MS = 3_600_000
GRACE_MS = 15 * 60_000
FIRST_LIVE_SLOT_MS = 1_794_582_000_000  # 2026-11-13T15:00:00Z
REQUIRED_KIND = "synthetic_heartbeat"
MAX_RECEIPTS = 200


def check_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Assess a bounded D1 row snapshot, reporting missing/invalid slots explicitly.

    Expected JSON: {"observed_ms":int,"first_expected_slot_ms":int,
      "rows":[{"slot_ms":int,"kind":"synthetic_heartbeat","scheduled_at_ms":int},...]}
    Caller must establish rows came from exact, live Cloudflare D1 independently.
    """
    if not isinstance(snapshot, dict) or set(snapshot) != {
        "observed_ms", "first_expected_slot_ms", "rows"
    }:
        raise ValueError("unexpected_snapshot_schema")
    now = snapshot["observed_ms"]
    start = snapshot["first_expected_slot_ms"]
    rows = snapshot["rows"]
    if type(now) is not int or type(start) is not int or now <= 0 or start <= 0:
        raise ValueError("invalid_clock_or_first_slot")
    if start % SLOT_MS:
        raise ValueError("first_slot_not_hour_aligned")
    if start != FIRST_LIVE_SLOT_MS:
        raise ValueError("unapproved_first_slot")
    if not isinstance(rows, list) or len(rows) > MAX_RECEIPTS:
        raise ValueError("too_many_or_invalid_rows")
    if now < start - SLOT_MS:
        raise ValueError("observation_clock_before_pilot")
    if now - start > 90 * SLOT_MS:
        raise ValueError("observation_outside_finite_pilot_window")

    invalid = []
    future_slots = []
    slot_occurrences: dict[int, int] = {}
    for i, row in enumerate(rows):
        if not isinstance(row, dict) or set(row) != {
            "slot_ms", "kind", "scheduled_at_ms"
        }:
            invalid.append({"index": i, "reason": "invalid_row_schema"})
            continue
        slot, kind, scheduled = (row["slot_ms"], row["kind"], row["scheduled_at_ms"])
        if type(slot) is not int or type(scheduled) is not int:
            invalid.append({"index": i, "reason": "invalid_time_type"})
            continue
        if slot > now:
            future_slots.append(slot)
            invalid.append({"index": i, "reason": "future_slot"})
            continue
        if slot % SLOT_MS or slot < start:
            invalid.append({"index": i, "reason": "unexpected_slot"})
            continue
        if kind != REQUIRED_KIND:
            invalid.append({"index": i, "reason": "unexpected_kind"})
            continue
        # scheduled_at_ms is a provider-supplied scheduled-event timestamp, NOT
        # a proven execution/completion timestamp. Do not infer actual latency.
        if not slot <= scheduled < slot + SLOT_MS or scheduled > now:
            invalid.append({"index": i, "reason": "invalid_scheduled_at"})
            continue
        slot_occurrences[slot] = slot_occurrences.get(slot, 0) + 1

    due_last = ((now - GRACE_MS) // SLOT_MS) * SLOT_MS
    if due_last < start:
        due_last = start - SLOT_MS
    required = range(start, due_last + SLOT_MS, SLOT_MS)
    missing = [slot for slot in required if slot not in slot_occurrences]
    duplicates = sorted(slot for slot, count in slot_occurrences.items() if count > 1)
    unexpected = sorted(set(future_slots))
    ordered = sorted(slot_occurrences)
    continuous_hours = (ordered[-1] - ordered[0]) // SLOT_MS if ordered else 0
    problem = bool(invalid or missing or duplicates or unexpected)
    return {
        "status": "FAILED" if problem else "PENDING" if not ordered else "CONSISTENT",
        "provenance": "snapshot_only_unverified_origin",
        "observed_ms": now,
        "first_expected_slot_ms": start,
        "first_recorded_slot_ms": ordered[0] if ordered else None,
        "latest_recorded_slot_ms": ordered[-1] if ordered else None,
        "unique_receipt_slots": len(ordered),
        "expected_due_slots": len(required),
        "missing_slots_ms": missing,
        "duplicate_slots_ms": duplicates,
        "invalid_rows": invalid,
        "unexpected_future_slots_ms": unexpected,
        "continuous_24h_window": not problem and continuous_hours >= 24 and len(ordered) >= 25,
        "continuous_48h_window": not problem and continuous_hours >= 48 and len(ordered) >= 49,
        "note": "Source authenticity and actual invocation must be independently verified by Cloudflare official read-only D1 API."
    }


def main() -> int:
    p = argparse.ArgumentParser(description="Offline synthetic Cron D1 continuity witness")
    p.add_argument("snapshot", help="Path to bounded JSON snapshot from an independently verified D1 API read")
    args = p.parse_args()
    try:
        with open(args.snapshot, "r", encoding="utf-8") as fp:
            snapshot = json.load(fp)
        result = check_snapshot(snapshot)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "INPUT_ERROR", "error": str(exc)}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 1 if result["status"] == "FAILED" else 0


if __name__ == "__main__":
    sys.exit(main())
