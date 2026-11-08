# Universal Gateway Cloudflare Free capacity and deployment gate — 2026-11-08

**Status:** Source-backed capacity study and isolated code/tests ONLY. No Cloudflare account access, production host, device enrollment, payment or permission activation. Preserve the independent owner-only capability switch.

## Current published Free limits (recheck at provisioning)
- Cloudflare Workers Free: **100,000 Worker requests/day**, **10 ms CPU time per HTTP request**, up to **5 Cron Triggers/account**. Network and database wait time is not itself CPU time; the 10 ms CPU limit can still interrupt cryptographic/security-heavy requests.
- D1 Free: **5 million rows read/day**, **100,000 rows written/day**, **500 MB maximum per database**, **5 GB stored across the account**, max **10 databases/account**. Daily query caps are enforced, not guaranteed rollover capacity. All limits are shared with any other account workloads.
- D1 Free per-invocation query subrequests are subject to the Workers Free restrictions. The database is single-threaded per database, so a busy queue can bottleneck despite being under daily request limits.

Official references (retrieved Nov 8, 2026):
- https://developers.cloudflare.com/workers/platform/limits/
- https://developers.cloudflare.com/workers/platform/pricing/
- https://developers.cloudflare.com/d1/platform/limits/
- https://developers.cloudflare.com/changelog/post/2026-09-01-d1-free-tier-limit-enforcement/

## Lightweight device polling estimates, NOT measured Cloudflare usage
Assumes each online enrolled device makes one `GET /v1/device/claim` per interval, no retries or other traffic; requests/day = devices * 86,400 / interval_seconds. All numbers exclude submit/completion requests, monitoring, cron triggers, failures/retries, and other account workloads.

| Online devices | Poll every | Estimated Worker requests/day | Free daily Worker request budget |
|---:|---:|---:|---|
| 10 | 60 seconds | 14,400 | 14.4% |
| 20 | 60 seconds | 28,800 | 28.8% |
| 50 | 60 seconds | 72,000 | 72.0% |
| 70 | 60 seconds | 100,800 | EXCEEDS |
| 50 | 300 seconds | 14,400 | 14.4% |
| 100 | 300 seconds | 28,800 | 28.8% |

**Controls planned, not installed:** polling jitter, bounded concurrency, exponential backoff and emergency stop; owner-configured daily consumption reserve/budget; explicit fail-closed quota handling; no automatic Paid-plan upgrade; read-only initial external smoke test; monitoring and capacity alarms. More devices or more frequent polling require fresh numbers.

## D1 row-write optimization actually implemented in isolated research branch
The earlier signed policy verification used an identical-row `INSERT ... ON CONFLICT ... UPDATE` on **every request**, consuming a D1 row write even for a repeated unchanged valid signed policy. The branch now persists a row only when receiving a *higher signed policy revision* and performs a read-only equality check for existing revisions. Submission/claim/completion still include database-backed revision guards to deny races or revoked grants.

- Evidence: the schema regression asserts that the total SQLite row-change count only increments for genuinely new revisions; a synthetic worker test verifies no repeated policy-revision writes; Windows, Linux, and local Cloudflare workerd/D1 tests run in GitHub Actions.
- LIMITATION: true Cloudflare production quota accounting, CPU timing, service cost, secret storage, identity proof and Internet reachability **are not yet measured**. Local workerd is not a Free account deployment. The queue still needs an independently authorized, authenticated agent on online devices.
- A powered-off primary PC cannot itself execute Windows diagnostics. The separately hosted gateway can accept/queue work while the PC is off and issue work after it comes back online.

## Gating decisions
Proceed with standalone owner-identity/attestation testing, encryption and audit design, realistic request performance tests and least-privilege device integration *without* production activation. Before provisioning any real service, obtain separately required approval, verify actual Free-plan account limitations and owner-controlled keys, and demonstrate a complete recovery plan. **No remote permission-enabling endpoint belongs in the gateway.**
