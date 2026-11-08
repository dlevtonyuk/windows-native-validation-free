# Always-On Universal Gateway — Cloudflare Free Prototype

**Engineering status: TESTED OFFLINE / NOT DEPLOYED / NO PRODUCTION CREDENTIALS**

This generic code is intended for a **Cloudflare Workers Free + D1** independent control plane that can remain reachable while Windows or other device adapters are offline. It is not an MCP integration or installed gateway by itself.

## Current verified source

- `worker.mjs`: authenticated request submission, device claims/completion, deny-by-default **Ed25519 owner-signed capability policy**, exact operation/device scopes, idempotent job IDs, expired lease quarantine (no unsafe automatic replay), no capability-enabling endpoint, no shell execution.
- `schema.sql`: indexed D1/SQLite queue. Prototype stores payloads in **plain text** and therefore **must not process confidential or personally identifiable payloads**.
- `worker.test.mjs`: 14 synthetic tests including forged policy, disabled scope, auth failures, queued/offline device, duplicate IDs, lease completion and quarantine.
- `check_schema.py`: verifies SQLite schema compatibility.
- [Cross-platform evidence](https://github.com/dlevtonyuk/windows-native-validation-free/actions): free GitHub-hosted Windows and Linux CI. **D1 is mocked** in the Worker tests, and no Cloudflare API or paid runner is used.

## Universal architecture

1. Independently hosted control plane (Cloudflare Workers Free and D1 is a researched candidate), reachable when user's PC is powered off.
2. Device adapters connect outbound only when their device is online. Offline device jobs remain queued; actual PC control **cannot happen while PC is off**.
3. Users **alone** hold private Ed25519 signing keys and choose which exact capabilities, operations and devices to enable. Cloud verifier holds only public key and signed policy. No API exists to remotely enable capabilities.
4. Separate app adapters and Windows adapters; operation names are not remote shell command strings. Domain-specific record changes require their own granular authorizations, idempotency, audit and business control.
5. GitHub public standard-hosted Windows/Linux runners provide free generic CI only; no private operational data or credentials belong in this public repository.

## Needed for a production host (NOT completed)

- Provision a genuine Workers **Free** account and D1 database, without changing to any paid tier. Cloudflare states a Free account can prototype D1 and exceeding free D1 quotas causes operations to fail, not metered overage billing.
- Securely provision `DB` D1 binding and owner-only configuration `OWNER_PUBLIC_KEY_B64`, `OWNER_POLICY_JSON`, `OWNER_POLICY_SIGNATURE_B64`, `SUBMIT_TOKEN`, `DEVICE_TOKENS_JSON`. **Never commit secret keys, tokens, policy-signing private keys, or business records.** The owner signs policy OFF the gateway using trusted local software. Neither ChatGPT nor the Worker can sign capabilities for the owner.
- Test genuine Cloudflare D1 API behavior and availability on the Free plan; validate actual quotas, outage/recovery, throttle/rate limiting, replay, multi-device race behavior, device token rotation/revocation and audit storage.
- Add production OAuth/OIDC or equivalent robust actor authentication, device cryptographic identities, audit export, durable retry only for proven idempotent operations, protected result/retention controls, monitoring, versioned rollback and disaster recovery.
- Integrate an authenticated MCP-compatible gateway interface or supported connected-app action. Current GitHub integration alone does not grant access to Cloudflare or enable arbitrary Windows commands.
- Independently validate Windows 11 Home adapter and authorized one-time deployment. User alone enables device/action toggles.
- Perform a security review before exposing endpoints with non-test credentials, especially because this is a general automation gateway.

## Source-only template

`wrangler.example.toml` intentionally contains a nonfunctional D1 placeholder. Deployment requires a real account, owner-side secrets, database binding, read-only initial smoke test and explicit capability activation. Do **not** copy a private key to GitHub or ChatGPT, nor use an unrestricted self-hosted runner on a daily-use PC.

**Price verification:** Cloudflare's official documentation currently lists Workers Free and D1 Free. Limits and availability can change; verify them again before deployment. Never silently upgrade.
