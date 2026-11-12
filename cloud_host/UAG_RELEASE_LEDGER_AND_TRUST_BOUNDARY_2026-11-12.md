# UAG universal release authorization — cumulative research checkpoint (2026-11-12)

**Status:** Research branch only. **NO** production Cloudflare deployment, changes to live build triggers, Cron, D1 production schema, owner policy, signed credentials, accounting/payroll, Windows devices, or scheduled automations are authorized or made by this release-ledger work. User-authorized `/owner/*` Access setup remains intact.

## Live facts independently confirmed
- Production Worker: `windows-native-validation-free`, active version `e44ce7b1-9074-4f3b-89fe-e4b4478f9b11`; current D1 binding named `DB`.
- Account's existing Access app `UAG Owner Policy Staging` protects only `windows-native-validation-free.dlevtonyuk.workers.dev/owner/*`; exact owner-only policy. Prior independent external probe verified that requests to owner routes redirect to Cloudflare Access while health remains HTTP 200, unauthenticated job submission HTTP 401 and unauthenticated device claim HTTP 503.
- D1 readback on November 12: `jobs=0`, `owner_policy_state=0`, `owner_policy_stage=0`. No enabled Cron triggers; Worker remains locked.
- Github production build auto-runs from `research/uag-cloudflare-free-staging-20261110` (HEAD `c2a52cdee77e001d3355029372cb0c7af00b8d6c`), branch `protected:false`. Repo rulesets inventory empty; GitHub app actions use same GitHub owner principal as human user.
- Read-only Cloudflare Worker Builds API confirmed **production deploy command** `npx wrangler deploy --config wrangler.toml`, **build command** `npm install --no-save --ignore-scripts wrangler@4.158.0`, **root directory** `/cloud_host`, and **auto_build_enabled=true`. A build token exists for this Worker; its actual granted permissions have not been independently verified. Do not publicize any token values.

## Signed release verification plus durable anti-replay research
- Prior `owner_release_verifier.mjs` cryptographically checks Ed25519 signature against a pinned external public key and the exact proposed Worker artifact bytes (SHA-256). It additionally pins repository, branch, target Worker, source commit, issuance, expiry and monotonic revision.
- **New:** `owner_release_guard.mjs` validates release signature and artifact then atomically records a one-use release claim in a separate SQLite ledger through Python. It has no network access or deploy operation.
- **New:** `owner_release_ledger.py` uses SQLite `BEGIN IMMEDIATE`, unique release claims, per-Worker high-water revision, and a chronological reserve/finalize event log. Revisions are consumed *before* any external operation; failures, crashes and concurrent claims cannot retry the same revision.
- Critical safety fix: ledger **never silently creates a fresh database** during claim/read after loss, corruption or missing schema. Explicit `init` is a separately controlled operation. A lost DB is a hard failure until owner-controlled recovery reconciles highest revision from independent evidence; a deleted file cannot reset the replay counter through ordinary code paths. A database administrator with file-write rights still can tamper with the DB: this is NOT an immutable or tamper-proof audit trail.
- Test evidence: real local SQLite 10 tests; Node Ed25519 + ledger integration 6 tests (plus existing verifier and vault regressions); GitHub Linux CI and Worker `wrangler versions upload --dry-run` successful. Windows test at first failed due test-only unclosed SQLite connection on Windows (`with sqlite3.connect()` did not close file handle), subsequently fixed using `contextlib.closing` on `test_owner_release_ledger.py`. See latest CI for verified cross-platform outcome.
- CI build: https://github.com/dlevtonyuk/windows-native-validation-free/actions?query=branch%3Aresearch%2Fuag-release-ledger-20261112
- Cloudflare official docs explicitly state `wrangler versions upload` creates a Worker version **without promoting traffic**; `--dry-run` compiles without uploading, tested on disposable GitHub runner.

## Important correction: upload-only Builds is NOT sufficient by itself
- Cloudflare Workers Builds requires a deployment-capable build token. Official docs: the automatically generated Build token typically grants Worker Scripts Edit and other scopes. Source: https://developers.cloudflare.com/workers/ci-cd/builds/configuration/
- A malicious modification to code, dependencies, build process or build tooling in an assistant-writable branch might use an available build credential. Thus changing the *command* from `wrangler deploy` to `wrangler versions upload` is a necessary risk reduction, **not** a cryptographically secure owner-only release gate when untrusted code can run with the build token.
- Future trusted production deploy credentials must be isolated from **all** assistant-editable scripts and builds. Verify actual Cloudflare build-token permissions, scoped Worker roles, and repository GitHub app installation permissions; never assume current token can be used safely for unattended untrusted builds.
- GitHub Free supports protected deployment environments with required human reviewers **for public repositories** (current repo public). But the approving GitHub principal is shared with the assistant's connector, and environment-protection alone does not make assistant-editable workflow steps trustworthy. Source: https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments
- A truly owner-only release lane requires an independent protected actor (owner-controlled account/service/repository and protected immutable verifier/release credentials), owner-held signing private key, independently pinned public key and policy, and durable high-water storage. An isolated free cloud account/service is a **candidate**, not yet verified/provisioned. Do not request one piece at a time; ACCESS-002 requires global scope and one complete user-facing intervention once design is demonstrably ready.

## Long-term execution architecture (not production authorization)
1. **Develop** synthetic and source-read-only adapters in assistant-writable research branches, no privileged secrets.
2. **Verify** build artifacts, signatures, change review, simulated side-effects, quotas, timeouts, D1 replay/rollback and Access identity in ephemeral CI.
3. **Owner-controlled approve/promote** a fixed source artifact in a protected production lane, with rollback and version readback. No model-accessible release-secret path; independent trusted store for revision/restore proof.
4. **Execute** cloud-native deterministic jobs 24/7 within Cloudflare Free quotas where available, independent of the laptop. Use Cron/D1 or, if its 24h retention/10k operations per day are adequate, free Cloudflare Queues. Provision only with separate deployment approvals.
5. **Operate** read-only Workyard/Zoho/finance adapters with isolated secrets and explicit source authority; transition to writes/payroll approvals only under separately verified business authorizations.
6. **Monitor** latency, free-tier quota exhaustion, stale queues, host failures, released versions, D1 Time Travel, credential health, signed policy expiry, revocation and recovery, with meaningful failure alerts. Reuse user's existing hourly gateway-related scheduled task if it can access tools; never create overlapping tasks for appearance. No additional paid services or ChatGPT Work mode.
7. **Retain local device bridge only for true desktop-only work**, keeping Windows processes windowless and permission-scoped, with primary PC-off limitations explicitly tracked.

## Open security and authorization gates
- Real owner signing key and recovery custody are not provisioned. CI keys are disposable.
- Trusted production runner, protected deployment credentials, and independent durable ledger host are not yet provisioned. Research SQLite is **not** persistent across GitHub ephemeral runs and is NOT a production replay store.
- GitHub production branch and Cloudflare Build token remain uncontrolled by an independent owner gate; signed release verifier is only prototype.
- No promotion, real business jobs, credentials, triggers, apps, policy activation, or approved production modifications.
- Future owner decision must cover **the complete release-trust architecture in one consolidated procedure**, not repeated narrow steps.

**Rule source:** latest approved `Universal_Principles_ACCESS-002_APPROVED_Complete_Master_2026-11-12.md`. This checkpoint is project research, not a substitute for the universal master.
