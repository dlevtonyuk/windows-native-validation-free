"""Offline Workyard/Zoho allocation reconciliation, non-mutating.

Input JSON is a private local Workyard snapshot; CSV is a private local
Zoho export. Never place actual organization/employee data in public CI.
Output is aggregate-only by default; --private-details emits IDs locally.
"""
import argparse
import csv
import io
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

REQUIRED_ZOHO = (
    "time_card_id", "allocation_id", "allocated_secs", "time_card_status",
    "time_card_start_dt_unix", "workyard_project_id", "cost_code_id",
    "time_card_updated_at_unix", "synced_at",
)
STATES = ("approved", "processed", "submitted", "working")
COMPARE_KEYS = (
    "time_card_id", "allocation_id", "allocated_secs", "time_card_status",
    "time_card_start_dt_unix", "workyard_project_id", "cost_code_id",
    "time_card_updated_at_unix",
)

class IncompleteEvidence(ValueError):
    """Inputs cannot support a trustworthy full-coverage conclusion."""


def _integer(value, label):
    try:
        if isinstance(value, bool) or value is None or str(value).strip() == "":
            raise ValueError
        result = int(str(value))
    except (ValueError, TypeError) as exc:
        raise IncompleteEvidence(f"invalid integer: {label}") from exc
    return result


def _seconds(value, label):
    try:
        if isinstance(value, bool) or value is None or str(value).strip() == "":
            raise ValueError
        n = float(value)
        if not (-1e15 < n < 1e15) or int(n) != n or n < 0:
            raise ValueError
        return int(n)
    except (ValueError, TypeError) as exc:
        raise IncompleteEvidence(f"invalid seconds: {label}") from exc


def _key(value, label, *, nullable=False):
    if value is None or str(value).strip() == "":
        if nullable:
            return ""
        raise IncompleteEvidence(f"missing key: {label}")
    return str(value).strip()


def _snapshot(source, start, end):
    if not isinstance(source, dict) or not isinstance(source.get("pages"), dict):
        raise IncompleteEvidence("Workyard JSON must provide statuses and all pages")
    if _integer(source.get("start_unix"), "start_unix") != start or _integer(source.get("end_unix"), "end_unix") != end:
        raise IncompleteEvidence("Workyard snapshot period does not match requested period")
    observed = source.get("queried_statuses")
    if not isinstance(observed, list) or sorted(observed) != sorted(STATES):
        raise IncompleteEvidence("The four required comparison statuses must be explicitly queried")
    records, counts = [], {}
    for status in STATES:
        raw_pages = source["pages"].get(status)
        if not isinstance(raw_pages, list) or not raw_pages:
            raise IncompleteEvidence("missing status/page: " + status)
        rows = []
        total = None
        lastpage = None
        for ix, page in enumerate(raw_pages, 1):
            if not isinstance(page, dict) or not isinstance(page.get("data"), list):
                raise IncompleteEvidence("invalid page data: " + status)
            meta = page.get("meta") or {}
            if _integer(meta.get("current_page"), "current_page") != ix:
                raise IncompleteEvidence("pagination gap/ordering: " + status)
            n = _integer(meta.get("total"), "total")
            lp = _integer(meta.get("last_page"), "last_page")
            if n < 0 or lp < 1 or (total is not None and total != n) or (lastpage is not None and lastpage != lp):
                raise IncompleteEvidence("inconsistent pagination meta: " + status)
            total, lastpage = n, lp
            rows.extend(page["data"])
        if len(raw_pages) != lastpage or len(rows) != total:
            raise IncompleteEvidence("unfetched page or inconsistent total: " + status)
        counts[status] = total
        for c in rows:
            if c.get("status") != status:
                raise IncompleteEvidence("status mismatch inside response: " + status)
            records.append(c)
    seen_cards, seen_allocs = set(), set()
    rows, candidates, card_sums, kinds = {}, [], Counter(), Counter()
    sample_unknown = 0
    for c in records:
        cid = _key(c.get("id"), "card_id")
        if cid in seen_cards:
            raise IncompleteEvidence("duplicate card across statuses/pages")
        seen_cards.add(cid)
        started = _integer(c.get("start_dt_unix"), "card start")
        updated = _integer(c.get("updated_at_unix"), "card update")
        if not start <= started < end:
            raise IncompleteEvidence("card outside local period: " + cid)
        summary = c.get("time_summary_v2") or {}
        expected = _seconds(summary.get("duration_secs"), "card duration")
        allocations = c.get("cost_allocations")
        if not isinstance(allocations, list) or not allocations:
            raise IncompleteEvidence("card without allocation: " + cid)
        summed = 0
        for a in allocations:
            aid = _key(a.get("id"), "allocation_id")
            if aid in seen_allocs:
                raise IncompleteEvidence("duplicate allocation")
            seen_allocs.add(aid)
            secs = _seconds(a.get("duration_secs"), "allocated secs")
            summed += secs
            if a.get("is_sample_data") is not False:
                sample_unknown += 1
            project = _key(a.get("org_project_id"), "project_id", nullable=True)
            code = _key(a.get("job_code_id"), "job_code_id", nullable=True)
            configured = (a.get("org_project") or {}).get("cost_code_ids")
            if configured is None or not isinstance(configured, list):
                raise IncompleteEvidence("unknown cost code configuration")
            if not project:
                kinds["missing_project"] += 1
            elif not code and len(configured) > 0:
                kinds["configured_project_uncoded"] += 1
                candidates.append({"time_card_id":cid,"allocation_id":aid,"project_id":project,"duration_secs":secs,"configured_code_count":len(configured),"time_card_status":c["status"]})
            elif not code:
                kinds["unconfigured_project_uncoded"] += 1
            else:
                kinds["coded"] += 1
            rows[aid] = {
                "time_card_id":cid,"allocation_id":aid,"allocated_secs":secs,
                "time_card_status":c["status"],"time_card_start_dt_unix":started,
                "workyard_project_id":project,"cost_code_id":code,
                "time_card_updated_at_unix":updated,
            }
        if summed != expected:
            raise IncompleteEvidence("card allocation duration does not reconcile: " + cid)
        card_sums[c["status"]] += expected
    if sample_unknown:
        raise IncompleteEvidence("sample-data provenance not confirmed")
    return rows, counts, dict(card_sums), kinds, candidates, len(seen_cards)


def _unzoned_sync(stamp):
    """Compare recorded sync ordering only; never assign a timezone."""
    try:
        return datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return None


def _classify_historical_extra(direct, other, sync_by_allocation, discrepancies):
    """Only mark extras as superseded when matched current card history proves it.

    An extra Zoho row is NOT a duplicate just because it has an old sync time.
    We must find the current card in the authoritative direct Workyard snapshot,
    independently match every one of that card's current allocation rows, and
    require both a prior source update AND an earlier Zoho sync for the extra.
    Any ambiguity remains unexplained and blocks current-equivalent acceptance.
    """
    mismatched_ids = {aid for aid, _ in discrepancies}
    current_matches = (set(direct) & set(other)) - mismatched_ids
    current_by_card, matched_by_card, current_sync_by_card = {}, {}, {}
    for aid, row in direct.items():
        cid = row["time_card_id"]
        stamp = row["time_card_updated_at_unix"]
        if cid in current_by_card and current_by_card[cid]["updated"] != stamp:
            raise IncompleteEvidence("inconsistent updated_at across direct allocations")
        if cid not in current_by_card:
            current_by_card[cid] = {"updated":stamp, "allocations":set()}
        current_by_card[cid]["allocations"].add(aid)
        if aid in current_matches:
            matched_by_card.setdefault(cid,set()).add(aid)
            sync = _unzoned_sync(sync_by_allocation[aid])
            if sync is not None:
                prev = current_sync_by_card.get(cid)
                current_sync_by_card[cid] = max(sync, prev) if prev else sync
    historical, unexplained = [], []
    for aid in sorted(set(other)-set(direct)):
        row = other[aid]
        cid = row["time_card_id"]
        now = current_by_card.get(cid)
        earlier = _unzoned_sync(sync_by_allocation[aid])
        current_sync = current_sync_by_card.get(cid)
        is_proven_prior = (
            now is not None
            and matched_by_card.get(cid,set()) == now["allocations"]
            and bool(now["allocations"])
            and row["time_card_updated_at_unix"] < now["updated"]
            and earlier is not None and current_sync is not None
            and earlier < current_sync
        )
        (historical if is_proven_prior else unexplained).append(aid)
    return historical, unexplained


def compare(workyard_json, zoho_csv, start_unix, end_unix, *, private_details=False):
    """Compare complete source snapshots; no network or writes.

    Raises IncompleteEvidence for missing/invalid coverage. A result with
    complete=True but match=False is a real source discrepancy, not a success.
    """
    start, end = _integer(start_unix, "start"), _integer(end_unix, "end")
    if start >= end:
        raise IncompleteEvidence("invalid time period")
    direct, by_status, card_times, kinds, candidates, cards = _snapshot(workyard_json, start, end)
    text = zoho_csv.lstrip("\ufeff")
    csv_rows = csv.DictReader(io.StringIO(text))
    # Zoho V2 SELECT exports may prepend a SQL table alias ("t.") to each
    # header. Normalize only that known prefix and reject collisions; never
    # silently overwrite a field if both forms appear in the same export.
    if not csv_rows.fieldnames:
        raise IncompleteEvidence("missing Zoho export columns")
    original_names = csv_rows.fieldnames
    clean_names = [name[2:] if name.startswith("t.") else name for name in original_names]
    if len(set(clean_names)) != len(clean_names):
        raise IncompleteEvidence("ambiguous duplicate Zoho export columns")
    if set(REQUIRED_ZOHO) - set(clean_names):
        raise IncompleteEvidence("missing Zoho export columns")
    other = {}
    syncs = set()
    sync_by_allocation = {}
    for raw in csv_rows:
        if None in raw:
            raise IncompleteEvidence("malformed csv extra columns")
        if set(raw) != set(original_names):
            raise IncompleteEvidence("malformed csv shape")
        x = dict(zip(clean_names, (raw[name] for name in original_names)))
        a_id = _key(x.get("allocation_id"), "zoho allocation_id")
        if a_id in other:
            raise IncompleteEvidence("duplicate Zoho allocation")
        stamp = _key(x.get("synced_at"), "zoho synced_at")
        # Zoho does not provide timezone here, so no UTC freshness assertion.
        syncs.add(stamp)
        sync_by_allocation[a_id] = stamp
        t = _integer(x["time_card_start_dt_unix"], "Zoho start")
        if not start <= t < end:
            raise IncompleteEvidence("Zoho export outside period")
        other[a_id] = {
            "time_card_id":_key(x["time_card_id"], "Zoho card"),
            "allocation_id":a_id,
            "allocated_secs":_seconds(x["allocated_secs"], "Zoho seconds"),
            "time_card_status":_key(x["time_card_status"], "Zoho status"),
            "time_card_start_dt_unix":t,
            "workyard_project_id":_key(x["workyard_project_id"], "Zoho project",nullable=True),
            "cost_code_id":_key(x["cost_code_id"], "Zoho code",nullable=True),
            "time_card_updated_at_unix":_integer(x["time_card_updated_at_unix"], "Zoho update"),
        }
    unmatched_direct = sorted(set(direct)-set(other))
    unmatched_zoho = sorted(set(other)-set(direct))
    # Do not silently ignore unsettled source statuses. Surface a private-ID-free
    # status breakdown so a scheduled run can distinguish missing submitted
    # coverage from approved/processed mismatches, while still failing closed.
    missing_by_status = Counter(direct[aid]["time_card_status"] for aid in unmatched_direct)
    discrepancies = []
    for aid in set(direct)&set(other):
        for field in COMPARE_KEYS:
            if direct[aid][field] != other[aid][field]:
                discrepancies.append((aid,field))
    discrepancies.sort()
    exact = not unmatched_direct and not unmatched_zoho and not discrepancies
    historical, unexplained = _classify_historical_extra(
        direct, other, sync_by_allocation, discrepancies)
    current_equivalent = not unmatched_direct and not unexplained and not discrepancies
    raw_zoho_seconds = sum(v["allocated_secs"] for v in other.values())
    historical_seconds = sum(other[aid]["allocated_secs"] for aid in historical)
    # Do not count a test passing as evidence that all source statuses exist.
    result = {
        "complete":True, "exact_match":exact,
        # This supplementary result never conceals historical rows in raw Zoho.
        "current_snapshot_match":current_equivalent,
        "historical_zoho_allocations":len(historical),
        "historical_zoho_hours":round(historical_seconds/3600,6),
        "unexplained_zoho_allocations":len(unexplained),
        "raw_zoho_hours":round(raw_zoho_seconds/3600,6),
        "current_equivalent_zoho_hours":round((raw_zoho_seconds-historical_seconds)/3600,6) if current_equivalent else None,
        "review_required":bool(historical) or not current_equivalent,
        "period_unix":{"start":start,"end_exclusive":end},
        "card_count":cards,"statuses":by_status,
        "hours_total":round(sum(card_times.values())/3600,6),
        "hours_by_status":{k:round(v/3600,6) for k,v in card_times.items()},
        "direct_allocations":len(direct),"zoho_allocations":len(other),
        "exact_allocations":len(set(direct)&set(other))-len(set(aid for aid,_ in discrepancies)),
        "missing_in_zoho":len(unmatched_direct),"missing_in_workyard":len(unmatched_zoho),
        "missing_in_zoho_by_workyard_status":dict(sorted(missing_by_status.items())),
        "field_mismatches":len(discrepancies),
        "code_classifications":dict(kinds),
        "code_review_candidates":len(candidates),
        "candidate_hours":round(sum(c["duration_secs"] for c in candidates)/3600,6),
        "sync_timestamps_unzoned":sorted(syncs),
        "caveats":["Cross-API reads are not atomic", "Zoho synced_at lacks timezone", "Code omission is a review candidate, not a verified policy violation", "Historical Zoho snapshots can inflate raw sums; classify only with a newer matching Workyard card version"],
    }
    if private_details:
        result["private_exception_ids"]={
            "missing_in_zoho":unmatched_direct,"missing_in_workyard":unmatched_zoho,
            "historical_zoho_allocation_ids":historical,"unexplained_zoho_allocation_ids":unexplained,
            "field_mismatches":discrepancies,"cost_codes":candidates,
        }
    return result


def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workyard",required=True)
    ap.add_argument("--zoho",required=True)
    ap.add_argument("--start-unix",type=int,required=True)
    ap.add_argument("--end-unix",type=int,required=True)
    ap.add_argument("--private-details",action="store_true")
    a=ap.parse_args(argv)
    try:
        result=compare(json.loads(Path(a.workyard).read_text(encoding="utf-8")),Path(a.zoho).read_text(encoding="utf-8-sig"),a.start_unix,a.end_unix,private_details=a.private_details)
    except (IncompleteEvidence, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"complete":False,"error":str(exc)}),file=sys.stderr)
        return 2
    print(json.dumps(result,indent=2,sort_keys=True))
    return 0 if result["exact_match"] else 1

if __name__=="__main__":
    raise SystemExit(main())
