# UAG ACCESS-002: consolidated Cloudflare/GitHub permission preflight
**Verified:** 2026-11-12, API read-only checks. **Status:** RESEARCH; no modifications to Cloudflare Access apps, OAuth grants, schedules, GitHub repo rules or live Worker in this preflight.

## Existing user approval and limits
- User authorized inert /owner/policy/stage route, separate empty D1 owner_policy_stage table, and path-scoped Cloudflare Access owner authentication. These first two are implemented and independently verified. Path-scoped Access configuration is NOT implemented.
- User has **not** authorized enabling capabilities, real jobs, device controls, production payroll/accounting writes, automatic production schedules, or billing upgrades. No unrestricted operational access and no paid extras.
- Zero Trust Free organization is enabled and was verified via live API; the older "Access not enabled" error is obsolete.
- Gateway Worker: `windows-native-validation-free`; authenticated Cloudflare API account: `bf8a98a44fc97e6160f5c2b56994a9a7`; D1: `uag-staging-queue`, UUID `1b393fb4-7699-470d-8a78-5ef1d2af06c7`.
- Read-only D1 query 2026-11-12: `jobs=0`, `owner_policy_stage=0`, `owner_policy_state=0`; `owner_policy_stage` table exists.
- Current Worker deployments read succeeds (latest known Worker version `e44ce7b1-9074-4f3b-89fe-e4b4478f9b11`); cron trigger read succeeds, schedules empty.
- Connected official Cloudflare MCP works for API identity, Workers, D1; per-operation OAuth grants remain **partially** missing.
- Cloudflare API `GET /accounts/{account_id}/access/apps` returns MCP-side 403 specifically requiring one of `access.read`, `access.write` or `access.revoke`; use `access.write` for authorized POST create and `access.read` for inventory. `GET /access/identity_providers` requires `access-acct.read` or `access-acct.write`. User's earlier `access-app.*`, `access-policy.*`, `access-org.read` do NOT satisfy these specific API endpoints; never silently interchange namespace names.
- A failed `GET /user/tokens/verify` is **not** evidence that the official OAuth MCP connection is invalid: that endpoint verifies API tokens and returned Invalid API Token while regular OAuth-authorized Worker/D1 calls succeed. Do not ask for another reconnection based on this unrelated endpoint.
- OAuth scope counts **not discoverable** in the current connector; user previously reported 17 selected. Do not invent the identities of three extras.

## Core replacement OAuth scope set (17 requested for immediate approved work)
If the consent editor preserves earlier scopes, retain these where already selected and add only missing `access.read`, `access.write`, `access-acct.read`. If OAuth starts from scratch, select all names listed below explicitly, *not* the generic `Full access` preset:

```text
account-settings.read
account-analytics.read
workers-scripts.read
workers-scripts.metadata_read
workers-ci.read
workers-observability.read
d1.metadata_read
d1.read
d1.write
access-org.read
access-app.read
access-app.write
access-policy.read
access-policy.write
access.read
access.write
access-acct.read
```

The 14 older scopes alone do not grant the documented Access application API operations. Added permissions are account-level Access application and policy management; never use them to widen access to unrelated resources without separately approved scope. `d1.write` is powerful, includes database deletion API; user authorized **only an idempotent staging schema**, not broad D1 mutations.

Conditional, **do not request yet**:
- `workers-tail.read` if current observability does not permit required logs.
- `notifications.read` / `notifications.write` if Cloudflare alert configuration is approved; no evidence these are required for current Access.
- `workers-scripts.edit` / `workers-scripts.write` if later approved remote Cron or Worker code deployment; **withhold until owner-exclusive release gating**, because these scopes can potentially replace verifier code.
- `access-acct.write` only if the default Cloudflare identity provider is absent and user approves its creation (new 2026 Zero Trust orgs get default Cloudflare identity provider).
- `queues.metadata_read` / `queues.read` / `queues.write` only if D1 queue cannot meet approved workloads; avoid unnecessary paid features.
- Unrestricted Full Access, `account-api-tokens.write`, billing changes, DNS, broad security rewrites, secret-store write, `workers-scripts.admin`, identity revocation and Access Revoke are out of scope.

## Exact user-only OAuth edit path, with verified and unknown UI parts
Open **ChatGPT Settings > Plugins** (or Apps if Plugins is not shown), choose **Cloudflare API (official)**, locate the connected **Primary** account. The authenticated connection itself has been tested. Select **Reconnect** or **Edit connection** only where that actual control appears (label not available to the assistant; don't invent a screen); complete Cloudflare sign-in. At Cloudflare's consent permissions interface that the user already described, choose **Edit Permissions** under Full access, NOT blanket Full access. Retain existing approved grants, add `access.read`, `access.write`, `access-acct.read`, or select the complete 17 if the editor resets choices. Confirm the Cloudflare account identity, verify the displayed selected scopes, submit Cloudflare authorization, then confirm **Primary connected**. If no reconnect/edit option appears, inspect actual interface and request one tightly scoped screenshot rather than guessing/revoking the connection. Never share OAuth bearer tokens, passphrases or private keys in ChatGPT or GitHub. ChatGPT docs: https://help.openai.com/en/articles/20001494-connecting-and-managing-app-accounts-in-chatgpt

## Next actions already approved after OAuth verification (assistant-led)
1. Read Access application inventory and identity providers; confirm no existing equivalent app (avoid duplicates).
2. Create a **self-hosted Access app protected only at** `windows-native-validation-free.dlevtonyuk.workers.dev/owner/*`; match actual Worker routing and Access path semantics, and verify other public `/health`, non-owner API paths unchanged. Scope the rule to the verified owner Cloudflare account membership, not public domain wildcard / all email users.
3. Authenticate the account holder through the default Cloudflare IdP; apply least-privilege identity/policy. Until the private owner signing key is provisioned, the Worker should continue responding 403 even with Access (fail-closed).
4. Verify with an isolated, read-only external probe: unauthenticated owner request rejected at edge, public health still 200, unauthenticated submit denied, D1 shows zero jobs and zero active policy. Audit app id and audience; record version and rollback plan.
5. DO NOT create/sign an enabling policy or worker credentials. Real owner signer, recovery, and owner-gate require distinct acceptance and an owner-private secret never available to the assistant.

## Critical independent release-security finding
- GitHub `research/uag-cloudflare-free-staging-20261110` branch reports `protected:false`; `main` also `protected:false`; repo rulesets endpoint returned empty list. The stage branch is directly wired to auto-deploy through Cloudflare Builds.
- GitHub plugin uses the account-owner identity (`nickname=dlevtonyuk`) for repository operations. **A ruleset based solely on GitHub username does not separate assistant from human**, even if the token's endpoint permissions differ. Any assistant-editable release branch with auto-deploy is a bypass around Worker owner-signed policy checks.
- Before allowing real jobs, move deployment authority to **an owner-controlled, separately scoped trust boundary**. Research/dev branches remain assistant-writeable; owner releases must go through an independently guarded CI/GitHub environment or trusted owner-held signing gate. A generic `Require PR` rule with a one-person account is not automatically sufficient: verify no bypass using the connected GitHub app identity and avoid breaking CI. The repo is public; GitHub Free allows public-repo rulesets, but exact required-review and bypass semantics depend on actors and repo type.
- Never treat an owner's private Ed25519 signing key stored only outside ChatGPT as sufficient while the assistant can deploy arbitrary verifier code without separate guard.
- GitHub docs: https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/creating-rulesets-for-a-repository

## Workload roadmap and cost gates — not authorization
- Read-only monitoring/data adapters, D1 isolated synthetic queue, structured audit, scheduled Cloudflare Cron, exception handling and app-specific mappings, always-on off-PC operation. Cloudflare Workers Free at 2026-10-29 documented 100,000 requests/day, 10ms CPU/request, 5 Cron triggers/account; actual load and feature costs must be rechecked before use. https://developers.cloudflare.com/workers/platform/limits/
- Need a scheduled/cloud-side actor (not ChatGPT conversation itself) for unattended deterministic execution. Existing ChatGPT hourly task has Gateway-related instructions and must NOT be duplicated or rewritten without owner approval.
- Build Cloudflare Free readiness checklist, GitHub ownership-protected release process, quotas/backups/restore validation, synthetic 24h engine monitoring, then adapter-specific read-only tests. Do not turn on scheduling or business adapters merely because API scopes permit it.
- Portable vendor APIs/MCP, no prohibited execution modes, owner-controlled gating. Strict verification/authorization, no secret disclosure or billing modifications.

## Distinguish completed from open
**Completed**: live staging Worker route (inert), D1 table, connected Cloudflare MCP, zero-job D1 integrity, Zero Trust org creation, read-only API access, cross-platform CI tests.
**Open**: owner-only Access application (blocked by missing `access.*` OAuth grants), private owner signer, owner-exclusive GitHub/Cloudflare release barrier, recovery, quotas/alerts, authorized read-only workloads, independent scheduling, device adapters.


## Subsequent 2026-11-12 quota and recovery validation

- Cloudflare D1 Time Travel `GET /accounts/{account_id}/d1/database/{database_id}/time_travel/bookmark` returned success and a bookmark field. This proves **a bookmark exists**, not that point-in-time restoration has been tested. No restore or export occurred.
- Cloudflare D1 Free documented **5 million rows read/day, 100,000 rows written/day, 5 GB total storage, 10 databases**; daily limit enforcement went live September 1, 2026 and will reject queries after cap until midnight UTC. Source: https://developers.cloudflare.com/d1/platform/pricing/
- Workers Free documented **100,000 requests/day, 10ms CPU/request, 5 Cron triggers/account**, so time-based automation must be lightweight with conservative resource limits and no production scheduler yet. Source: https://developers.cloudflare.com/workers/platform/limits/
- Cloudflare Queues is now available under Workers Free with **10,000 operations/day**, but **24-hour max free retention**; this makes it a potential future durable task-dispatch alternative to the handcrafted D1 queue, provided idempotency and retention requirements are met. Not approved for creation or binding; API scopes remain optional until implemented and separately approved. Source: https://developers.cloudflare.com/queues/platform/pricing/
- GitHub `get_profile` confirms the connected repository app acts as the **account owner's GitHub principal**. A username-specific rule alone cannot guarantee separation from assistant-initiated API mutations; prefer app-scoped permissions, independent release gates, and positive tests before any claim of owner-exclusive repository deployments. The available GitHub connector lacks repository-administration endpoints, but that is a current tool limitation, **not a permanent security guarantee**.
- GitHub Free supports rulesets in public repositories, including the present public validation repo, but details such as the one-person pull-request approval flow and bypass privileges must be tested on a disposable branch first. Source: https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/creating-rulesets-for-a-repository
- A read-only probe of Cloudflare `GET /user/tokens/verify` returned `Invalid API Token` because this is an API token verification route, not a reliable OAuth grants inventory for this MCP connection. DO NOT interpret it as a failed app OAuth connection: authorized D1/Worker calls still work.


## 2026-11-12 VERIFIED COMPLETION: Cloudflare Access owner-only stage (supersedes older "missing scopes" language above)

The user reconnected the official Cloudflare API plugin and explicitly refreshed tools. Live read-only API calls verified **both** `GET /access/apps` and `GET /access/identity_providers`, removing the OAuth permissions blocker without requesting any other grant.

The assistant executed the previously user-approved path-specific Access configuration. Created exactly one self-hosted Access application (no prior apps existed), named `UAG Owner Policy Staging`, on `windows-native-validation-free.dlevtonyuk.workers.dev/owner/*`; scope is only a single public Worker hostname/path. It uses the existing Cloudflare default identity provider, already configured `restrict_to_account_members:true`, with an additional exact owner-email-only allow policy. No broad public Access rule, Worker-wide Access rule, another Worker, billing modification, additional identity provider, or enabled jobs.

API response and readback verified the newly created app, one allow policy, matching exact domain, identity-provider restriction, hidden app-launcher listing, and 2-hour session limit. Its application ID is `5b57ebde-fd95-44db-8c84-3ea7c5e17621` (not a credential); policy ID `72a5de45-acbe-456d-aa46-5b248449a42a`. **Do not post user email, Access sessions, private keys, or secrets in public GitHub.**

Real live externally hosted GitHub Action URL: https://github.com/dlevtonyuk/windows-native-validation-free/actions/runs/43215153302

Verified responses:
- `GET /health` => 200, exactly `{"service":"universal-gateway","status":"no_public_capabilities"}`.
- `GET /owner/policy/stage` => 302 redirect to the account's Access login host.
- `POST /owner/policy/stage` => 302 to Access login host.
- `GET /owner/test` => 302 to Access login host (covers the wildcard path).
- `POST /v1/jobs` without bearer token => 401 Unauthorized.
- `GET /v1/device/claim?device=office_pc` => 503 `device_tokens_unconfigured`.
- Existing D1 prior to Access app creation: `jobs=0`, `owner_policy_stage=0`, `owner_policy_state=0`. Creating Access app does not write D1.

**Completed:** approved standalone owner Access application and edge-level denial; no more reconnect or Zero Trust enrollment required. The external probe tests *unauthenticated* requests only, not a live owner login session. The Worker handler still lacks production `OWNER_ACCESS_AUD`/`OWNER_ACCESS_EMAIL` and owner-public-signing-key configuration, intentionally fail-closed. No owner private key is present. No active production workloads.

**Remaining global gate:** the auto-deployed GitHub staging branch is `protected:false` and there are zero repository rulesets; a trusted, owner-exclusive release boundary must be established before any real jobs or owner-only toggles can be considered secured against assistant-initiated code replacement. Do not enable Cron, real device credentials, business APIs or elevated Worker write scopes as a workaround.
