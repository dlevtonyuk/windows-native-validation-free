# UAG isolated off-PC synthetic Cron: single-deployment candidate

**Research candidate, not deployed, not approved for Cloudflare writes.**

Goal: Demonstrate an **actually scheduled, independent cloud job** which records exactly one persistent synthetic receipt per UTC hour, without the user's PC, privileged secrets, business records, or real operational effects. The research code supplies a fully inert bridge **only for this milestone**; it does not represent the universal Gateway running business tasks.

## Minimal design

- Isolated future Worker name: `uag-synthetic-cron-independent` (does not replace or modify current `windows-native-validation-free`).
- Isolated future D1 database: `uag-synthetic-cron-independent`, created only on the existing Cloudflare account **after explicit approval and account billing verification**.
- Only hourly scheduled handler writes `slot_ms`, fixed `kind=synthetic_heartbeat`, `scheduled_at_ms`; unique `slot_ms` makes retried triggers idempotent. No client-controlled job submission or completion routes; no secrets, customer information, or business adapters. HTTP supports only `/health`; all other paths return 404. The Worker includes no arbitrary command path or outbound HTTP request.
- A provider-scheduled handler invokes a D1 insert once per hour. The Cloudflare API (authorized read-only query) can independently establish chronological proof: `SELECT slot_ms,kind,scheduled_at_ms FROM synthetic_cron_receipts ORDER BY slot_ms DESC LIMIT 5`. Cron inventory and deployments must be read back separately.
- The first live test requires one **single consolidated authorization** to create the Worker and dedicated database, apply this exact schema, deploy this exact reviewed Worker, and enable a defined synthetic hourly schedule. No business integrations or new operational capabilities are implicitly enabled. Never automatically extend this authorization to Workyard, Gusto, banking, real Windows control, or communication actions.
- A live heartbeat is **not** proof of owner-exclusive release control, independent real-device agents, general task authorization, billing, or full Gateway readiness. Those remain distinct further gates.

## Hard stop and budget gate

Cloudflare Free pricing documentation supports a limited free Worker/D1/Cron execution tier, but the **actual account's Workers billing plan cannot be read from currently connected OAuth scopes**. Account type `standard` and Worker usage model `standard` do **not** identify Free vs Paid. Verify an authoritative account-plan classification and cumulative existing-account quotas before any new deployment. No service purchase, plan change, billing authorization or charge is permitted. Abort if this cannot be verified as genuinely no additional charge.

## Safe research verification

`node --test cloud_host/synthetic_cron/test_worker.mjs`

The research GitHub workflow compiles a **dry run** with Wrangler, initializes disposable **local** D1, starts local `wrangler dev --test-scheduled` on disposable hosted Ubuntu, injects two local synthetic Cron events, and verifies exactly one durable receipt. CI must not read Cloudflare secrets, deploy, create Cloudflare resources, or access business systems.

## Later owner-approved rollout and rollback (NOT PERFORMED)

1. Before provisioning: verify actual Free account plan, usage quotas, and the original staging Worker/D1/version/trigger unchanged; approve exact synthetic resource names and hourly schedule, costs $0, no real effects.
2. Create isolated D1, apply `schema.sql`, fill actual new database UUID in a private deployment configuration; publish only reviewed compiled Worker and matching isolated schedule. Never substitute the existing production `wrangler.toml` or staging deployment branch.
3. Confirm `/health`, route denials, provider Cron inventory and first D1 synthetic receipt; verify scheduled execution on separate hours without relying on the local PC.
4. If verification fails, stop/disable the **new synthetic** Cron and preserve its evidence/database; do not touch existing Gateway resources. Any deletion/cleanup of cloud records/resources requires separate approval.
5. Log exact source SHA, compiled hash, Worker version, billing/plan evidence, D1 ID, Cron configuration, timestamps, readback and rollback status. Do not claim a live result based on local tests alone.

## Non-goals

This candidate deliberately **does not** control an independent Windows agent, persist private credentials, deploy owner signing material, release across untrusted principals or perform business actions. It is the smallest credible live off-PC scheduling milestone, not a substitute for later effect isolation and governance.
