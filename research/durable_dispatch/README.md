# Universal Gateway: durable, multi-job Cron research (no deployment)

**Status: offline research only. No Cloudflare account write, production deployment, real SaaS access, real device data or privileged effects.** The code contains no credentials and is safe to share only after independent public-source review.

This advances the Gateway beyond one row per hour: a **single native Cron** coordinates multiple discrete durable D1 jobs. A local workerd/D1 CI test exercises one scheduled tick containing three independently claimable synthetic read-only jobs, two success transitions, an injected failure with durable backoff, replay idempotence, an expired-claim recovery and three permanently held non-executable routes.

## Files
- `schema.sql`: durable job, tick and event tables with strong state constraints and indexes.
- `fixtures.sql`: six invented tasks; two cloud read-only mock jobs, one expired read-only claim, and blocked connector/device/owner-effect routes.
- `worker.mjs`: single-Cron D1 atomic claim, bound read-only simulated handler, retry, digest and lifecycle event. `POST` routes and real effect adapters **do not exist**.
- `test_worker.mjs`: negative access and deterministic UTC-time checks.
- `wrangler.lab.toml`: all-zero placeholder D1 UUID and no production endpoint.
- `workerd_acceptance.sh`: disposable local workerd/D1 true scheduled-invocation test; no Cloudflare token.

## Why this cannot be silently promoted to production
1. The only executable route is explicitly called `cloud_readonly_mock`; it returns a constant synthetic payload. ChatGPT's connected Workyard/Zoho plugins are **not** callable from Cloudflare and their credentials are not present here.
2. Durable state is a necessary but insufficient condition. The protected, independently owner-controlled signer and adapter are not yet deployed. Real actions require separate owner activation; a Worker that assistant can deploy cannot enforce owner-exclusive effect approval on its own.
3. The Free plan's ~10ms CPU/invocation, 50 subrequests per invocation and account-wide D1/Queue/Workflow daily limits still require actual Cloudflare runtime/billing metrics before use. The local workerd test proves behavior, not production Cloudflare reliability or specific pricing.
4. A job claimed by an external side-effectful executor may have unknown outcome after an interruption. This prototype deliberately **does not** implement external effects; only retry-safe internal synthetic reads may be reclaimed.
5. The design stores no actual payroll/employee/customer or API data and uses no network to third-party providers. Staged read-only integration with a real source must be separately authorized and audited before code promotion.
6. The `dispatch_events` table is a research audit supplement; it is not an immutable, cryptographic owner audit or a complete production event-sourcing solution. Production needs reconciled transactional completion plus signatures and failure-injection verification.

## Acceptance
`node --test research/durable_dispatch/test_worker.mjs` and `bash research/durable_dispatch/workerd_acceptance.sh` on a disposable Ubuntu GitHub runner. Native Windows and Linux run unit tests. The local test asserts 1 Cron receipt, 2 successful tasks, 1 delayed retry, 3 blocked routes, 0 duplicated effects, 0 exposed operational HTTP endpoints and correct real SQLite D1 persistence; it explicitly does **not** claim business-system connectivity.

Future productive path: cloud scheduler + D1 persistent state, ChatGPT connector lane running only in actual unattended ChatGPT tasks until a separately provisioned protected broker exists; then owner-approved read-only SaaS adapter and finally individually scoped privileged-effects adapters. No recurring user prompts for routine authorized reads; no unjustified capability activation.
