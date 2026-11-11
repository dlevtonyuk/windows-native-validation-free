# Universal Execution Architecture — Cloudflare direct-management route (2026-11-11)

**Status:** Verified vendor-supported integration plan; **NO new Cloudflare/ChatGPT OAuth connection established, no account permissions granted, and no additional live deployment.** This research branch is isolated from GitHub `main` and the Cloudflare connected staging branch. The owner explicitly requested a **global, long-term, zero-additional-cost authorization and execution architecture** rather than serial dashboard instructions.

## Breakthrough: use the official Cloudflare API MCP, not a custom one

Cloudflare itself maintains an OAuth-authenticated remote MCP server:

- Endpoint: **https://mcp.cloudflare.com/mcp**
- Official docs: https://developers.cloudflare.com/agents/model-context-protocol/cloudflare/servers-for-cloudflare/
- It exposes `search`, `execute`, and `docs` to traverse Cloudflare's documented API: Workers, D1, Access/Zero Trust, metrics, etc.
- It advertises more than 2,500 API endpoints, but **only the Cloudflare permissions granted by the account owner** are usable. Do not infer resource access until a read-only call proves it.
- It supports owner OAuth consent. **Never post API token, account password, OAuth access token, bearer token, or owner private signing key in a conversation, repository or log.**

OpenAI's plugin instructions: https://help.openai.com/en/articles/12584461-connecting-custom-mcp-servers-in-chatgpt and https://developers.openai.com/api/docs/guides/custom-mcp-server.

**One-time user connection path IF supported on the user's current account:** ChatGPT Plugins > + > Add custom MCP server > name "Cloudflare API (official)" > Connection server URL `https://mcp.cloudflare.com/mcp` > OAuth sign-in with Cloudflare > review exact requested API scopes and security warning > create/install the plugin. Some ChatGPT plans/workspaces may not expose this UI; do not claim connection, entitlement, or persistence before testing the tool list. **Do not recommend the prohibited ChatGPT Work mode.**

## Permission boundaries for maximizing useful autonomy

1. Read-only Cloudflare resource inventory, settings, build/deployment status, D1 schema, usage quotas, event logs, and Access policy metadata first.
2. After owner-selected authorization, management writes scoped to **the EXISTING Worker `windows-native-validation-free`**, **D1 database `uag-staging-queue`** (UUID `1b393fb4-7699-470d-8a78-5ef1d2af06c7`), and a path-scoped Access app for `/owner/*`. Use per-resource roles where available, least-privilege account-level scopes only where Cloudflare cannot scope to one D1 resource. Prefer separate scopes for D1 Read, D1 Write, Workers Editor, and Access Apps write. **No account/global superadministrator, billing, domains/DNS, deletion, unrelated apps, or broad account access.**
3. Preserve **owner-only capability activation**: allowed infrastructure maintenance does NOT authorize enabled job policy, client device enrollment, shell/browser control, payroll/accounting writes, unrestricted tool execution, or business-data transfers.
4. The existing GitHub integration already auto-deploys pushes to `research/uag-cloudflare-free-staging-20261110`. Do not add another deployment path merely for appearance. Maintain candidate branches, preflight CI, source SHA attestation, owner risk checks, and rollback/recovery before promoting any verified code.
5. Once official MCP tools are actually present, independently (a) read current Worker, D1 and Access state, (b) apply the **already approved idempotent** `cloud_host/schema_stage.sql` to the existing D1, (c) verify `owner_policy_stage` exists and contains 0 rows, and (d) create/configure the owner-only Access app at precisely the existing workers.dev hostname + `/owner/*`. Confirm host/path precedence and owner allow policy; DO NOT protect the whole Worker and break health or future machine access.
6. The Access app still needs owner-controlled verified identity and an **owner-held** Ed25519 signing key. A real private key must be generated/kept in the owner-controlled security environment, not on CI or accessible to ChatGPT. The research `owner_policy_vault.mjs` is an offline prototype only and not a production-quality owner console.

## Strong separation between model-controlled code and owner authority

A model with arbitrary write/deployment authority to a Worker could replace the signature-checking code. Therefore, **signed authorization inside an assistant-deployable Worker alone is NOT independent enforcement**. Before real device/business capabilities, require (a) protected owner-controlled release/trust roots and independent code review for privileged code, (b) downstream agent-side validation of owner signature immediately before effects, (c) owner-controlled signing/rotation/recovery outside model-accessible systems, (d) append-only/auditable external execution decisions and emergency stop, and (e) scoped vendor credentials with no model-accessible exfiltration path. Protect high-risk workflow branches; no unrestricted superuser token.

## Actual off-device autonomy plan (phased, portable)

- Control plane: independently hosted free-tier Worker (live); D1 queue (live), disabled owner route (live); separate staging table/Access configuration pending.
- Management: owner-scoped official Cloudflare MCP with OAuth (not connected yet), existing GitHub read/write plugin and CI; supported provider APIs and scoped audit trails.
- Continuity: deterministic Cloudflare Cron/Queues/D1 with daily budgets, retry deadlines, dead-letter/quarantine and backups; no guarantee of 100% uptime, unlimited free compute, or ChatGPT model continuation without a supported automation.
- Workloads: build and validate **read-only** connected API adapters before adding owner-approved writes; keep accounting/payroll/business data away from public GitHub and synthetic fixtures.
- Laptop: only truly local Windows/desktop operations need a least-privilege on-demand local agent; an off PC cannot perform local desktop tasks.
- Zero-cost boundary: no additional paid subscriptions, credit cards or custom domains without user authorization; monitor quotas and provider terms.

## Status / remaining blockers

- Cloudflare Workers deployment of the inert `/owner/policy/stage` route succeeded on Nov 11, 2026. Remote /health HTTP 200, owner staging POST without Access HTTP 403, unauthenticated job POST HTTP 401 confirmed from GitHub runner. HTTP 403 error 1010 on default Python User-Agent for device claim came from Cloudflare workers.dev Browser Integrity Check, not the Worker; use a descriptive `User-Agent: uag-ci-verification/1.0` rather than attempting to disable this global Cloudflare edge protection. Source: https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-1xxx-errors/error-1010/
- Existing D1 `jobs` and `owner_policy_state` were verified by owner: counts 1/1, jobs 0. New `owner_policy_stage` schema migration NOT applied. Access app NOT created, owner public key NOT provisioned.
- No Cloudflare management plugin is connected through the current tools. Direct REST/API access cannot be synthesized from GitHub repository access.
- **Minimal new user action for maximal future access:** connect official Cloudflare MCP in ChatGPT once, selecting appropriate OAuth permissions. If no custom MCP connection is possible on this account, fall back to owner-scoped Cloudflare API token stored in a **protected** CI environment, never in a repo/chat; do not invent GitHub permission/security protections or assume secrets safe on unprotected writable feature branches.

**One source of truth for this workstream:** live staging branch; owner-control research branch `research/uag-owner-stage-gate-20261111`; this plan's research branch; latest approved universal rules including CONTINUITY-001; original `ARCHITECTURE.md` in ChatGPT Library. This plan does not replace or silently supersede any of those originals.
