# Offline owner-control and synthetic cloud-executor research (2026-11-11)

**Status:** Offline prototypes tested in disposable GitHub CI; **not deployed**. Live Cloudflare Worker and D1 remain on the owner-locked staging branch with no authorized jobs, devices, or secrets. Public repository: NO confidential work data, owner private keys, passphrases, bearer tokens, or signed production grants.

## What has actually been implemented

1. `synthetic_agent.mjs`: a narrowly allowlisted test actor that can call the Worker queue via HTTPS, claim only `synthetic_probe:echo` for `cloud_runner`, echo a 1–96 character safe nonce, acknowledge the result, and reject all other jobs. It cannot invoke a shell, read files, use applications, or inspect the user's computer. Its loopback HTTP exception exists only to exercise local workerd in CI.
2. `test_workerd_integration.mjs`: an actual Cloudflare local runtime + D1 test of synthetic policy grant, durable queue, lease, completed result, duplicate prevention, and invalid-credential denial. All tokens/Ed25519 keys are generated or hardcoded **test-only** identities in an ephemeral runner.
3. `owner_policy_vault.mjs`: offline-only encrypted Ed25519 owner key format using scrypt plus AES-256-GCM, signatures with strict revision, expiry (at most 90 days), and capability-scope checks; signature format matches Worker WebCrypto verification. The key is never transmitted by this code.
4. `owner_policy_vault.test.mjs` verifies encrypted key and signature handling; key material created inside public CI is **disposable**, intentionally unsuitable for the real owner's account.
5. Prior `worker.mjs` also has 4 KiB streaming limits, bounded credential handling, D1 revision checks, and revoked-job quarantine on this **research** branch; these refinements are not in live staging.

## What has NOT happened

- No real owner signing identity has been generated, installed, registered, or published.
- No owner authentication console/passkey login, encrypted recovery or key rotation policy is complete. The library is not a finished owner-facing application.
- No production Cloudflare secrets, Cloudflare Cron, external scheduler, real agent/device registration, live job execution, or business data migration.
- GitHub-hosted CI is used **only** to develop/test the adapter. It is **not** an authorization or plan to use GitHub Actions as a general-purpose commercial background compute service. Production compute must use legitimate supported services/free-plan resource budgets.
- The device executor has no pre-side-effect owner policy fetch: safe only because the synthetic action has no external effects. Do not generalize it to real computer or business actions without an atomic authorization and revocation design.

## Owner-only deployment gate

The real owner should create and retain an encrypted signing identity in a private, owner-controlled environment, with independently verifiable backup/recovery; **not** in this repository, a ChatGPT message, a CI runner, or the Cloudflare Worker. Owner approval requires a human-verifiable capability/operation/device/expiry/revision confirmation; the cryptographic library alone is not an adequate account-identity verification system.

A signed grant must only be placed in the Worker through an authorized, separately accepted owner provisioning process. Worker receiver credentials must be long random secret bindings, NOT committed to GitHub. A password-protected key file is not a replacement for owner MFA or passkey attestation.

Before any live proof, benchmark Worker Free 10 ms CPU and D1 rows, verify D1 schema/state, provide quota reserve/monitoring, and prove owner kill-switch/revocation after leasing. All real external actions require their own authorized scope.

**Goal:** Continue independently without involving the user's Windows PC except when a true local application is needed; no production changes without owner approval.
