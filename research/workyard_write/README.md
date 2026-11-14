# Workyard real-operation viability — safe API contract preflight

**November 14, 2026 — research only, no credential or application write.**

Verified public reference: https://developers.workyard.com/; https://help.workyard.com/en/articles/9499860-integrating-with-workyard-s-api

- Workyard REST API supports `PUT /orgs/{org_id}/time_cards/{time_card_id}` (a **full replacement**), `PATCH /orgs/{org_id}/time_cards/{time_card_id}/approve`, and the batch approval endpoint. No new developer account is needed if the org already has its authorized API token and qualifying plan. Rate limit: 60 requests/minute; `GET /time_cards` is limited to one simultaneous in-flight request per API user.
- The currently installed private Workyard connector provides **five read-only methods only**, not edit or approve. Its `get_time_card` response for a real card lacks `time_approver_id` and `cost_allocation_selections` required for a safe full PUT replacement; it must NOT be passed straight back as an edit payload. Other optional operational fields may need full preservation, too.
- The dry-run preflight deliberately protects **cost-code-only** modifications, refuses missing source fields, break changes, stale timestamps, project removal, malformed percent allocations, unknown configured codes, omitted reason, processed statuses lacking separate policy confirmation, and all approval attempts not `submitted`+`is_approvable`.
- Even passing this static preflight does NOT authorize or execute a write: `requestTransport='NONE'`, `effectEnabled=false`. Real runtime requires an independently protected owner-signed capability, bounded timecard scope, complete source snapshot including authoritative worksite/project selections, contemporaneous re-read/optimistic concurrency testing, proof of request/response and before/after state, and failure-safe idempotency + rollback procedure. PUT might be unsafe for a card if server-side behavior is not fully understood; do not force it.
- Owner's objective: one class-level activation per agreed safe operating boundary, not prompts for every routine authorized action. The separate protected broker must remain unreachable by assistant-editable Cloudflare Worker code. Never change app records, payment calculations or payroll without appropriate authorization.
- In real read-only audits, a missing code on a project with configured codes is a review candidate, not proof of an accounting or policy violation. Establish the employee/group rule and the correct allocation before considering a modification.

These generic public research files contain no real business IDs, employee names, tokens, private records or production deployment code. Run `node --test research/workyard_write/test_preflight.mjs`.
