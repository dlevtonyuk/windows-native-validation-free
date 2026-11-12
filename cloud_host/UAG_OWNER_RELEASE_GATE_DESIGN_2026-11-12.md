# UAG owner-exclusive release verification — research checkpoint (2026-11-12)

## Purpose and trust boundary

An owner-signed *capability policy* is not a sufficient security guarantee when the same assistant can push new code to the Worker that is supposed to enforce that policy. Cloudflare currently auto-deploys the GitHub branch `research/uag-cloudflare-free-staging-20261110`, which the GitHub API reports as **unprotected**; the GitHub connector can update it using the account owner's GitHub identity. We must therefore introduce an **independent owner-controlled release authority** before authenticating devices, granting business-service tokens, or activating scheduled work.

## Independent prototype delivered

- `cloud_host/owner_release_verifier.mjs` verifies one signed release manifest using a pinned **public** Ed25519 key and the **actual bytes** of the artifact proposed for deployment (SHA-256).
- Identity is pinned to an exact repository, exact branch, target Worker, 40-character source commit, and monotonic release revision.
- It rejects expired or future-issued approval, signature tampering, unexpected fields, altered source bytes, cross-target substitution, stale revision and unknown key.
- `cloud_host/owner_release_verifier.test.mjs` uses disposable, in-memory Ed25519 keys only. Neither real owner keys nor account secrets are committed.
- `.github/workflows/uag-owner-release-verifier.yml` tests this *offline* on Windows and Linux. The verifier does **not** deploy code, grant any permissions, invoke Cloudflare, or approve any release.

**Critical caveat:** Running this code only in an assistant-writable repository is not an independent trust boundary. An actor capable of modifying the verifier or deleting CI can bypass it; **do not deploy or call this secure production authorization** until an owner-controlled release process runs it and separately verifies the source hashes. The test also does not implement durable release revision storage.

## One-time long-term release architecture (design only)

1. **Assistant-controlled development:** Keep candidate branches, static tests, synthetic D1 tests, GitHub CI diagnostics, and documented approval artifacts accessible to the assistant. These paths must contain NO production secrets.
2. **Owner-controlled production release lane:** Disconnect the currently assistant-writable branch from unreviewed auto-deployment and establish a trusted release lane inaccessible to the assistant's GitHub/Cloudflare write identity. Use a separately protected GitHub environment, independent owner-controlled CI executor, or explicitly owner-controlled Cloudflare deployment approvals. Confirm the exact GitHub plan/account supports the chosen control and **test that the assistant app cannot bypass it**. Mere GitHub `protected:true` is NOT sufficient without proven separation of principal and bypass rights.
3. **Owner signing custody:** Generate one production Ed25519 private key entirely in an owner-controlled environment; never enter its bytes/passphrase in ChatGPT, CI, or an assistant-editable repo. Provision only the public key in the trusted verifier, with recovery and rotation plan. The owner chooses which code and capabilities may be activated.
4. **Deterministic approval object:** Present a human-readable exact destination/repository/commit/artifact hash/release revision/time/expiry, sign locally, and require an independent trusted runner to validate the bundle and binary bytes before release. Deny on missing signature, stale revision, or any mismatch. Protect private deployment credentials from assistant-controlled PR workflows.
5. **Independent runtime enforcement:** Even after trusted code release, agents and downstream credential brokers must verify an owner signature before irreversible actions; isolate real service secrets and side-effect brokers from untrusted Cloudflare access. Durable replay protection and emergency stop must reside in the trusted boundary.
6. **Monitoring and rollback:** Audit account, source SHA, verified release revision, real Cloudflare version ID, D1 migrations, Access policy drift, quotas, kill-switch results, and restore rehearsal. Record evidence, not success claims based solely on CI.

## Remaining approvals and constraints

The user **approved only** inert `/owner/*` Access protection, owner-stage D1 schema and fail-closed route. This is already deployed and validated; authenticated owner interaction still requires externally held signing key and Worker identity configuration. No authorization for real device tokens, business operations, automation cron, release trust migration, account settings changes, GitHub ruleset changes, or paid services has been supplied.

**Status:** RESEARCH/ISOLATED TESTING ONLY. Do not silently create production artifacts, elevate OAuth permissions, change Cloudflare auto-deployment, disable protections, or ask the user for repeated piecemeal UI steps. Any owner intervention must be a single comprehensive end-to-end executable package under ACCESS-002.
