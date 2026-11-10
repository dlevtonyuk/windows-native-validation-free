# Universal Automation Gateway — Cloudflare Free owner-locked staging

**Scope: isolated smoke test only. No business adapters, owner credentials, D1 data, device enrollment, or real jobs.** The Worker **has not been deployed** merely because these files exist.

## Verified prerequisite

The owner has already created a Cloudflare Free account. The GitHub account and existing public research repository are accessible. No additional paid services, domains, credit cards or local Windows software are needed for this inert stage.

## Owner-controlled Cloudflare UI setup

1. Cloudflare Dashboard > **Workers & Pages** > **Create application** > **GitHub** (exact labels may evolve).
2. If requested, authorize Cloudflare's GitHub App for **only** `dlevtonyuk/windows-native-validation-free`, not all repositories.
3. Select repository `dlevtonyuk/windows-native-validation-free`; choose branch **`research/uag-cloudflare-free-staging-20261110`**, **NOT main**. Ensure that this is the branch Cloudflare will build/deploy.
4. For the EXISTING Cloudflare Worker `windows-native-validation-free`, go to Settings > Build > Branch control and set production branch to `research/uag-cloudflare-free-staging-20261110` (NOT `main`); disable preview builds if present. In Settings > Build > configuration, set root directory to **`cloud_host`**. The Worker name in the staging `wrangler.toml` now matches the existing Cloudflare Worker `windows-native-validation-free`; do not create or rename a Worker.
5. Build command: `npm install --no-save --ignore-scripts wrangler@4.158.0`.
6. Deploy command: `npx wrangler deploy --config wrangler.toml`. Turn off other branch previews/automatic extra builds if offered. Do **not** create any environment variables, secrets, D1 bindings, cron schedules, domains or paid resources.
7. Review settings and **only then** decide whether to click Save and Deploy. This is an owner-controlled activation of an **inert staging endpoint**, not an authorization to perform computer or business operations.
8. Verify that `/health` responds with JSON `{"service":"universal-gateway","status":"no_public_capabilities"}`. No user tokens or credentials should be entered or pasted in ChatGPT. Test denied requests through isolated CI instead of exposing any credential in browser or logs.

Cloudflare Workers Builds auto-deploys commits pushed to the configured production branch; do not treat branch configuration as automatic permission to add capabilities. Keep this feature branch fixed while staging remains active. Before changing the Worker or its policies, require an explicit owner decision and separate signed permission grant.

## Why this is fail-closed

* No `SUBMIT_TOKEN` or `DEVICE_TOKENS_JSON`: jobs, claims and completions cannot authenticate.
* No `OWNER_PUBLIC_KEY_B64`, `OWNER_POLICY_JSON`, `OWNER_POLICY_SIGNATURE_B64`: no valid owner-signed capabilities.
* No `DB` binding: no durable queue is configured.
* The Worker exposes a synthetic public health response only. It must never hold private business data on this public repository.

## Subsequent gates — NOT authorized by this staging config

1. Independently benchmark Cloudflare Free CPU quota (10 ms per HTTP invocation) on account, and verify no billable upgrades; look at failures and usage in dashboard.
2. Harden large-body handling, token limits, on-device pre-effect authorization, owner-only signing control, key rotation, least-privilege access and abuse protection; validate offline and with synthetic test data.
3. Add owner-approved D1/database, retention and backup controls, then demonstrably test data recovery with synthetic records.
4. Prove separate cloud business adapter with read-only scope; do not transfer app credentials without secure owner action.
5. Device endpoint requires a separately validated lightweight agent; **a gateway does not remove browser rendering from the local PC**.

The design goal is perpetual $0 at current terms, not a guarantee that providers cannot change Free limits.

## Fresh-build provenance check (November 10, 2026)

The owner's Cloudflare settings screenshot verifies production branch `research/uag-cloudflare-free-staging-20261110`, root directory `/cloud_host`, and deploy command `npx wrangler deploy --config wrangler.toml`. A failed build attempted to read `/opt/buildhome/repo/cloud_host/wrangler.toml`, which exists on this staging branch but is absent from the repository's `main` branch. Retrying an earlier build may reuse its original source revision, even after branch settings change. This documentation-only commit intentionally generates a NEW push event on the correct staging branch so the connected Cloudflare integration can build the current staging source. This commit makes no Worker code or permission changes. Observe the new build's source branch/commit and health response before any additional changes. If no build is triggered, do not change main or grant additional capabilities: investigate GitHub webhook/integration delivery and Cloudflare build trigger status.
