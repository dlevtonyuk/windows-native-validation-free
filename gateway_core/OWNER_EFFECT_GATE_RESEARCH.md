# Adapter-side owner effect gate — non-deploying research candidate

**Research only; not deployed and NOT independent owner-only production security.**

## Threat model and purpose

The current Cloudflare Worker's code can be edited by connected automation tooling, so a Worker-only policy or release check does not constrain a malicious/compromised Worker. Before connecting real business records or physical devices, every side-effecting adapter must independently reject instructions outside an owner-signed narrow lease. Owner consent for a *capability class* should permit bounded unattended operations; it does not imply approval for unbounded arbitrary commands.

The public repository contains only inert, synthetic code and disposable-test keys. The owner private key and real device credentials must never be available to this repository, model, Cloudflare Worker or cloud CI. A real deployment would install the adapter gate in a **trusted execution context inaccessible to the assistant**, with pinned public key and trusted local persistent state. These access and installation conditions are NOT met by this prototype.

## Evidence-backed offline slice

- `owner_effect_gate.mjs`: Node built-in Ed25519 verification against a host-pinned public key; strict scope `(gateway_id,device_id,capability,operation)`, active revision, exact SHA256 of payload bytes, expiry/lifetime and claim budget. The publicly exported execution API always re-verifies the signed grant before reserving. There is no remote command registry or network action.
- `owner_effect_ledger.py`: an explicit-only trusted-host SQLite state store. No automatic recreation on loss. Owner-verified higher revisions revoke older grants; atomic `BEGIN IMMEDIATE` claims enforce per-lease budget and never replay a job ID, even across restarts. A crash leaves a reserved claim consumed and requires owner-trusted reconciliation. Stored records intentionally contain neither request payloads nor credentials.
- Tests generate **disposable Ed25519 keys** and use a local synthetic payload and a fake handler. A cross-language integration uses actual, disposable local SQLite on native Windows and Ubuntu; no actual Windows or business capability is enabled.
- A present or correctly signed grant does not authorize its own activation: a separate owner-trusted activation layer must verify and store the active revision. It must not accept untrusted network requests to call the ledger `activate` function.

## Boundaries and remaining work

1. Trust isolation is not provided by tests: the entire verifier, pinned public key, policy revision, ledger, adapter binaries, and their update channel must be protected from the assistant's existing GitHub/Cloudflare permissions. Security cannot be claimed merely because a signature verifies in assistant-editable code.
2. The fixed payload digest is a deliberately narrow initial class. Reusable business parameters require separately approved typed schemas, trusted adapters, bounded effects and field-level data controls; no shell or arbitrary-code operation may be introduced.
3. SQLite is not a tamper-proof independent ledger; a principal able to modify the file or both its binary and signature checker can forge state. Shared-device, offline-retention, concurrency, credential custody, revocation, owner recovery and rollback need actual trusted-host design and separate approval.
4. Owner-only activation must be once per bounded capability class and lease; routine execution remains autonomous within the signed limits and existing business approvals. No routine human signature per queued job is required.
5. **No deployment, real device access, external calls, Cloudflare/D1 modification, secrets, expenses, other repositories or permissions changes are authorized or performed by this research.**

## Reproduce with free local tools

```sh
python -m unittest discover -s gateway_core -p test_owner_effect_ledger.py -v
node --test gateway_core/owner_effect_gate.test.mjs
```

The GitHub research workflow executes both on hosted Windows and Ubuntu with no production credentials.
