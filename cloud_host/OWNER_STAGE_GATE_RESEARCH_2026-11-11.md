# Owner-policy stage gate — verified research, not deployed

**2026-11-11.** This branch is deliberately separate from:
- live Cloudflare production branch: `research/uag-cloudflare-free-staging-20261110`
- repository default branch: `main`

The live Worker, owner D1, laptop, and Scheduled Tasks have **not** been changed by this research.

## Implemented in this branch

- `cloud_host/owner_stage.mjs`: only `POST /owner/policy/stage` under the `/owner/` namespace; every other owner route returns 404.
- `cloud_host/worker.mjs`: route integration preserving existing health response and job endpoints.
- `cloud_host/schema_stage.sql`: **candidate**, not applied to the remote database. Creates an independent `owner_policy_stage` table.
- `cloud_host/owner_stage.test.mjs`: Cloudflare Access owner identity/audience checks, tamper/replay/cross-origin denial, disabled-policy-only acceptance, bounded input.
- `cloud_host/check_owner_stage_sqlite.py`: real SQLite atomic monotonic revision test; distinct from active `owner_policy_state`.
- `cloud_host/test_workerd_integration.mjs`: real disposable workerd+D1 test proves requests without Cloudflare Access are denied by the integrated route.
- Existing encrypted owner-key research stays separate; no production owner key was created or published.

## Exact security boundary

Only synthetic disabled grants are acceptable here. `synthetic_probe` is the sole supported capability; `enabled` must be `false`. The only device/operation strings are `cloud_runner` / `echo`; no job is dispatched and no active-owner-policy row is changed. The endpoint requires both (1) Cloudflare-authenticated `ctx.access` with a matching Access application AUD and the exact owner email and (2) independently signed Ed25519 JSON matching the pinned public key. The endpoint has no fallback trust in HTTP headers. Its separate D1 row is version-monotonic, and the client cannot decrement the row with an older signed revision.

Cloudflare's published 2026 Access Workers documentation confirms `ctx.access`, `ctx.access.aud`, and `ctx.access.getIdentity()` for directly Access-authenticated Worker requests. Caveats: `ctx.access` is not propagated through Service Bindings or the static-assets router; local Wrangler Access identity simulation is for test only. The Worker must remain without a static-assets routing layer unless this is independently redesigned.

## Before considering a live rollout

1. Obtain separate owner approval specifically to deploy the inert `/owner/policy/stage` endpoint and create the empty `owner_policy_stage` table. Research/CI permission is NOT deployment permission.
2. Confirm exact owner account identity and Access application audience via an owner-controlled Cloudflare Free account login, not in a public repo. Keep owner email and session tokens confidential. Protect `/owner/*` with path-targeted Access, **not** Worker-wide Access: blocking the whole Worker could disrupt machine/API requests or the public health endpoint. Verify actual hostname/path coverage and Access app precedence first.
3. Provision a verified owner public signing key and Access audience/email through owner-controlled Worker settings; never post owner private key, passphrase, authentic Access JWT, bearer tokens or production credentials to a chat or GitHub.
4. Review owner login/MFA/passkey, recovery, owner-visible policy confirmation, replay/revision recovery, audit, retention, encrypted backup, and emergency stop. A signed policy does not automatically authorize external business or device operations.
5. After fresh deployment approval: run Cloudflare CI dry run, verify deployment commit/version, verify health and existing API fail-closed behavior, stage a **disabled** synthetic policy only, and verify D1 no active grants and no queued jobs. Never deploy real jobs or business adapters as part of the same authorization.

## Current verified test evidence

Workflow: https://github.com/dlevtonyuk/windows-native-validation-free/actions/runs/43082558474

- Windows Server 2025: 58/58 Node tests and local SQLite staging contract PASS.
- Ubuntu: 58/58 Node tests and local SQLite staging contract PASS.
- Disposable Cloudflare workerd + D1: signed synthetic execution and Access-less owner staging denial PASS; Wrangler dry-run passes.
- No remote Cloudflare D1 schema changes, account Access settings, credentials, laptop actions, or default branch changes.

**References:** https://developers.cloudflare.com/workers/configuration/cloudflare-access/ and https://developers.cloudflare.com/workers/runtime-apis/bindings/service-bindings/
