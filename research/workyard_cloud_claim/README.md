# Workyard owner-private cloud claim research (20 Nov 2026)

**NON-DEPLOYING RESEARCH ONLY. No production credentials, personal data, API calls, settings updates, payroll effects or authorizations.**

## Purpose

The pre-existing 43-test Workyard approval candidate protects a single approval with a local file claim. This local file **is not durable across ephemeral GitHub-hosted runners**; a recurring runner could re-attempt a card after restart. The added `private_claims.py` introduces an independently durable **owner-private GitHub repository claim**, committed before any Workyard approval attempt and read back before releasing the effect. The test suite injects a fake GitHub transport and a fake Workyard approval gate. Both contain synthetic identifiers only.

## Trust requirements (NOT satisfied merely by these files)

1. Execute a separately owner-reviewed, pinned copy inside `uag-owner-control-private`, which stays **excluded** from the ChatGPT/GitHub App installation. This public research repository is untrusted; it must never have the owner token, Workyard bearer token, Gusto credentials, private signing key, or producer execution rights.
2. The private workflow alone supplies the authenticated, HTTPS-only `api.github.com` transport and protects its `GITHUB_TOKEN` and deployment. The owner's `approval_policy.json`, active grant revision, release hashes and source code are **not** editable by the assistant.
3. Before each action, the owner-trusted approval gate enforces the preflight, local-time period, source revision, signer grant, cohort/project exceptions and note/alert/offsite holds. The cloud wrapper **does not implement** signature verification or replace that gate.
4. Use an exclusive concurrency boundary for each Workyard organization; no other owner workflows or devices may bypass the durable claim store. Never reset/delete claims to retry without owner-only reconciliation of the remote Workyard status.
5. A GitHub API claim commit **is a production effect in the private owner's repository**. Such writes, transfer of any Workyard credentials, creation/activation of scheduled approval jobs, timecard approvals or Gusto processing require separate explicit authorization. None have occurred.
6. Owner-private signed OIDC telemetry receipts are **not** job or payroll authorization, and assistant-writable Cloudflare Workers cannot be trusted as execution guards.

## Safe acceptance scenario

- Owner-private runner reads submitted timecards from the Workyard API using an owner-private secret and a fixed, reviewed org/period policy.
- For each candidate, it checks signoff, notes, exceptions and existing Gusto/PTO/job-costing rules; ambiguous cards are held.
- It writes a deterministic, exclusive one-time claim in the private repository and independently verifies that claim **before** an approval PATCH.
- The independently protected Workyard approval gate re-reads the source and checks owner policy, then approves once; the runner records a receipt and reconciles the readback.
- A crash, 429, unknown write result, lost ledger readback or duplicate job never triggers an automatic retry.
- Workyard-to-Gusto export and final payroll are **separate acceptance gates**, not implied by approval. The public API does not provide a verified native Gusto export operation.

## Test

```bash
python -m unittest -v test_private_claims.py
```

14 tests pass with a fake GitHub transport and fake approval gate on Python 3.13. This establishes only code-level fail-closed behavior. It does **not** prove GitHub API permissions, private repository integration, timecard approval, durable real-world outage recovery, Windows behavior, or Gusto export.