# Owner gate: D1 connection to the inert Cloudflare gateway

**Status: prepared offline; not deployed, not bound to the live Worker, no remote SQL executed.**

The owner supplied D1 UUID `1b393fb4-7699-470d-8a78-5ef1d2af06c7` after creating the free staging database `uag-staging-queue`. This UUID identifies a resource; it is NOT an API key or proof that this repository can access that resource. Validate name and plan in Cloudflare's D1 dashboard before activation.

## Files and isolation

- Current live source: branch `research/uag-cloudflare-free-staging-20261110`, `cloud_host/wrangler.toml`, intentionally **no D1 binding**.
- Prepared candidate: branch `research/uag-d1-offline-20261110`, `cloud_host/wrangler.d1.pending.toml`, binding `DB` to `uag-staging-queue` using the owner-provided UUID.
- Schema: `cloud_host/schema.sql` is generic job metadata and owner-policy watermark only; contains no business rows.
- Application: `cloud_host/worker.mjs` denies job submissions, device claims, and completion without a valid signed owner policy and independent long random bearer tokens.
- GitHub Actions tests use `--local` D1 and `--dry-run` packaging. Neither can initialize or bind the owner's remote D1 database.

## Validation and future activation

1. In a disposable GitHub Actions runner validate: TOML, no credentials, unchanged live staging config, local SQLite/D1 schema, 26 Node authorization tests, offline workerd with D1, and no-cost Wrangler dry-run packaging.
2. After owner explicitly authorizes the **inert database binding only**, promote the verified candidate `[[d1_databases]]` block to the Cloudflare production branch `cloud_host/wrangler.toml` and verify the build and health response. No owner-signed policy or device token is supplied. **Keep branch and Worker name exactly as currently configured.**
3. After separate permission to initialize empty staging D1 tables, apply the approved `schema.sql` (dashboard D1 Console or remote Wrangler using an owner-controlled Cloudflare credential; never share a token in ChatGPT). Verify `jobs` and `owner_policy_state` exist and that `jobs` is empty.
4. Review quota usage, Cloudflare Free plan, 7-day point-in-time recovery, backup/export policy, and owner authentication before enabling real jobs.
5. Real job execution remains **blocked** until the owner controls an independently signed valid policy plus provisioned secrets, a least-privilege agent, and workload-specific authorization. The database binding alone is not an enable-capability decision.

**Important:** Cloudflare may build preview branches automatically, but this candidate does not modify the active staging `wrangler.toml`. Never deploy `wrangler.d1.pending.toml` to the owner's Worker without a fresh owner approval.

## No-cost and reliability

D1 Free account quotas are enforced; exceeding them causes request errors until midnight UTC, not automatic paid upgrade. Do not guarantee perpetual availability or terms. Do not use GitHub Actions as an unrelated always-on business compute service; keep it to source-control CI, tests, and legitimate deployment. Remote scheduled workloads may require further owner decisions and additional vendor API credentials.
