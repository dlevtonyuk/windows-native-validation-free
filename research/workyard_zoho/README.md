# Generic read-only Workyard–Zoho reconciliation witness

**Research code; no production deployment, credentials, network traffic, or write capability.**  This is an adapter-neutral *offline* parser. The code cannot call Workyard, Zoho, Cloudflare, ChatGPT, or any business account. It does not turn a scheduled ChatGPT task into an independent cloud executor. Production deployment and changes to accounting/timecards are expressly out of scope.

## Acceptance contract

Only compare snapshots for a precisely bounded **local-time** reporting interval: start Unix seconds inclusive, end Unix seconds exclusive. The caller must convert organizational local timestamps (including DST) to seconds *before* invocation. Never infer that UTC midnight equals local midnight. Independently query and fully paginate the four **observed, known API statuses** `approved`, `processed`, `submitted`, `working`. `processed` is not the same as `approved`. Do not claim these four exhaust every possible Workyard state: additional valid provider statuses must be discovered and explicitly added to coverage when verified. Never infer that an invalid query means zero records.

The private Workyard JSON input wraps every requested status in a complete list of pages (exact API `meta.current_page`, `meta.last_page`, `meta.total`, and `data` for each page), and lists the four queried statuses and precise period. Preserve real source item fields including `cost_allocations`, `time_summary_v2`, `updated_at_unix`, `start_dt_unix` and the boolean `is_sample_data`. Separately export only these Zoho source columns from its existing **Workyard Data - Time Card Details** table: `time_card_id`, `allocation_id`, `allocated_secs`, `time_card_status`, `time_card_start_dt_unix`, `workyard_project_id`, `cost_code_id`, `time_card_updated_at_unix`, `synced_at`. Use `SELECT` only, through authenticated read/export APIs; no records are edited. Keep raw exports locally/private, never push them or credentials into a public repository, hosted test runner or chat task prompt.

The witness fail-closes for missing pages, duplicates, wrong statuses, out-of-range dates, malformed amounts, unknown project code configuration, sample data, unreconciled per-card allocation seconds, schema errors or missing sync fields. It compares **eight** fields between sources on the unique allocation ID, including source update time. It distinguishes `missing_project`, `configured_project_uncoded` (review candidate only), `unconfigured_project_uncoded` (not automatically compliant), and `coded`. The default output contains aggregate-only numbers; full private exception IDs require `--private-details` on a trusted local environment.

Example (fictional private local files; **do not** commit live JSON/CSV):

```bash
python research/workyard_zoho/reconcile.py --workyard private_workyard.json --zoho private_zoho.csv --start-unix 1000 --end-unix 2000
```

Exit 0: input coverage is complete and all compared allocations equal; exit 1: complete source snapshots, but discrepancies exist; exit 2: insufficient/unsafe evidence. A successful comparison **does not** prove Gusto payroll totals, PTO/UTO, project business-policy correctness, timecard approval eligibility, source-to-payment correctness, or that no other Workyard states exist. It proves precisely the observed source fields for that time window. Zoho `synced_at` has no trustworthy zone indicator; report it without assigning a UTC offset. The two systems have no common snapshot transaction, so a concurrent source update can require a retry. Success must be backed by actual independent authenticated reads or scheduled-run receipts, not an offline test alone.

## Hosted tests and security

The CI workflow below checks fictional fixtures only on GitHub-hosted Windows and Ubuntu, without environment credentials or deployment. `permissions: contents: read`; no Cloudflare or Workyard tokens, no network calls from the test program. This research is compatible with the user's existing non-deployment GitHub research branch. Production credentials and real data stay outside GitHub Actions.
