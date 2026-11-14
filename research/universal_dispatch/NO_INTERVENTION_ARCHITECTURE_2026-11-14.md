# Universal Execution Architecture — minimal-to-no intervention, capacity and trust preflight

**Research artifact, November 14, 2026. NOT production deployment authorization.**

## Explicit objective and definition of done

User outcome: **Once the owner approves a recurring capability class and its boundaries, normal executions should require zero manual prompting, copy/paste, browser tab management, computer restarts, or user-mediated transfers.** Reserved new capabilities, exceptionally consequential transactions, MFA and credential renewal may still require an owner action; the system must bundle those into a single exact, comprehensive intervention, not serial piecemeal steps. Do not silently enable new capabilities or reduce existing permissions.

**Completion gate — operational foundation:** at least one *genuine useful connected read-only workflow* executes unattended, draws from a real authorized source, validates its findings, persists resumable status and evidence, alerts only on actionable exceptions, and requires no user prompt. A synthetic heartbeat or successful interactive connector call alone does not satisfy the gate. A universal architecture later needs multiple independently authorized services or environments, trusted side-effect authorization, recovery and offline-device handling.

## Verified current access and footprint

- A user-confirmed Workers **Free** plan must still be checked against independently measured account-wide use; API `standard` is **not independent billing proof**. Never purchase or change a plan in this preflight.
- This publicly releasable research contains **no account identifiers, deployment IDs, connected-provider organization details, scheduled-task IDs, credentials, operational data, or business records**. Private account-specific observed quantities must remain in a separately access-controlled checkpoint.
- An interactive app-connector success does NOT prove unattended connector access. A ChatGPT scheduled task may use its available plugins; a Cloudflare Worker **cannot call those plugins** merely because they are installed in ChatGPT.

## One-roof-first execution topology

```
 OWNER (one-time capability class consent; holds signing secret; revocation)
               |
   INDEPENDENT TRUSTED EFFECT BROKER [not yet deployed]
               | only pre-approved exact effects; audit/replay controls
 Cloudflare (existing account, Free, scheduling + durable coordination)
   1 logical Cron dispatcher -> D1 durable state -> bounded short job fan-out
                           |                  |
                native Cloudflare/Queues  device-specific trusted adapter
                           |                  | (waits when device offline)
                           |                  +-- owner-signed one-use effects
                 external API/read-only adapter (only separately provisioned)

 Existing ChatGPT hourly task -> connected app/plugin read-only workflows
  (separate lane; runs if actual unattended connector access succeeds)
```

A single Cloudflare Cron rule can schedule many *logical* jobs; do not allocate a new Cron rule for every task. D1 is the durable source of truth, so Cloudflare Queues' **24-hour Free retention** is an optional delivery accelerator and NOT the only persistence for PC-off / service-down jobs. Free Workers **10 ms CPU/invocation**, 50 subrequests/invocation and D1/Queues/Workflows daily limits require short, bounded dispatch batches and downstream workers/adapters. CPU limit and real end-to-end throughput must be verified with workerd and actual Cloudflare analytics before any production claim; the capacity model is a preflight estimate, not a CPU benchmark.

**Cloudflare official limits observed 2026-11-14:** Free Workers 100,000 requests/day, 5 Cron trigger rules/account, 10 ms CPU/invocation, 50 subrequests/invocation; D1 5 million read rows/day, 100,000 written rows/day, 10 DB/account, 5GB total; Queues 10,000 operations/day with 24-hour max retention; Workflows 3,000 steps/day. Check official docs again before deployment and reserve **20% headroom** for other account usage; limit counters are account-wide. Sources:
- https://developers.cloudflare.com/workers/platform/limits/
- https://developers.cloudflare.com/workers/configuration/cron-triggers/
- https://developers.cloudflare.com/workers/platform/pricing/
- https://developers.cloudflare.com/queues/platform/pricing/
- https://developers.cloudflare.com/workflows/reference/pricing/

## Exactly how to minimize intervention

1. **Default zero routine prompts.** The owner makes one *class-level* activation decision, scoped by source, operation, device(s), spending/write caps, duration, emergency stop, and notification threshold. Repeat routine actions without new approvals only inside that grant; keep unknown scopes disabled. Choose revocation/expiration deliberately; never silently set an indefinite write grant in the name of convenience.
2. **Separate ChatGPT connectors from Cloudflare's Worker runtime.** The existing hourly task may use already connected app tools if scheduled-run access works. Native cloud code may call only separately configured provider APIs or trusted adapters with authorized token custody. Never copy app credentials or business records into a public GitHub repo or into a broadly assistant-editable Worker. An authenticated SaaS connection is not automatically a security grant to other hosts.
3. **Only owner-trusted adapters execute effects.** The scheduler and assistant-controlled source are untrusted, can suggest or enqueue *intent*, but cannot activate or bypass a protected signer or side-effect broker. Use the already-tested owner-effect gate (pinned Ed25519 verifier and replay ledger) in an independent protected runtime with explicit user deployment approval. A protected cloud runtime controlled by the same assistant Cloudflare write identity is not a genuine separate enforcement boundary. Reuse current accounts first, but do not claim this control exists before actual external negative-access testing.
4. **Offline PC doesn't stop cloud tasks.** Local-only tasks remain in durable `waiting_for_device`, never falsely succeed or automatically replay high-risk effects after a lease expires. Online services continue independently. A permanently offline PC cannot execute Windows-local commands: this is a physical constraint, not a cloud hosting defect.
5. **Quotas are observable stop conditions, not surprises.** Record actual daily usage, predicted per-job consumption and account-wide headroom; pause low-priority jobs before exceeding free quotas. Switch to D1-only batching, Workflows or a protected adapter if Queues would exhaust daily operations, with actual limits verified first. Never introduce a paid fallback or charge without user approval.
6. **Resilience is designed upfront.** Preserve idempotency key, immutable intent, owner-grant revision, last claim, attempt/failure history, absolute deadlines and recovery state. Distinguish retry-safe read-only operations from consequential actions whose outcome may be unknown. Implement dead-letter/exception states, reconciliation and verified rollback. Monitor missed deadlines not just heartbeats. No arbitrary-shell processing.
7. **Avoid user-as-middleman.** Use existing connected sources and existing authorized scheduled task before asking the owner for exports/screenshots/UI steps; before a necessary intervention, investigate 4–10 next dependencies and deliver ONE verified comprehensive batch of exact instructions. Inaccessible private signing credentials require owner custody; they cannot be created by assuming consent.
8. **Preserve alternatives without multiplying accounts.** Prefer existing Cloudflare account and GitHub research repository. Keep a portable connector/executor interface so another free provider can replace a component if independent evidence shows a hard limit, but do not create accounts, switch plan, disconnect integrations or distribute workloads unnecessarily.

## Host choice and real gaps (no optimistic claims)

| Boundary | Short-term mechanism | Genuine unresolved gate |
|---|---|---|
| Unattended read-only connected apps | Existing authorized ChatGPT hourly task and connected source tools | Next actual scheduled-run metadata tool access must succeed; then implement a useful read-only reconciliation |
| Cloud scheduling/DB | Existing Cloudflare Free Cron+D1 | 24/48-hour real proof; account-wide quota telemetry; D1 durable dispatcher code not deployed |
| Scalable workloads | Bounded dispatcher + D1 durable jobs, Queues/Workflows when quota supports | Real workerd + provider execution/resource accounting; rate limits and reconnect behavior |
| Owner-exclusive writes | Host-pinned signing and one-use adapter-side gate (research proven) | Actual independently protected runtime, key custody, policy UI, negative access tests, class-level approval |
| PC-off | Cloud API tasks continue; local-only work waits | Independent always-on host/adapter for any task requiring live desktop when primary PC is off; cannot execute on powered-off machine |
| Real effect credentials | Owner-trusted broker separate from untrusted source and Cloudflare Worker write identity | Secure deployment and credential provisioning require explicit user authorization; no broad secret access |

### Admission / no-manual-prompts gate

1. Scheduled ChatGPT tool reachability for an authorized read-only source established with real runs.
2. At least one real, safe, read-only business validation runs on schedule and emits an actionable exception/result. No manual user forwarding.
3. Results have stable job IDs, source timestamps, completeness/coverage, and can survive transient failure.
4. Cloud bridge and protected adapter are promoted only after exact approved one-time owner grant and verified minimal-owner-intervention deployment.
5. Cross-cloud/PC-off failover, 7+ day reliability and real recovery exercise before general production-hardened claim.

**Research-only scope:** This source and CI may be tested on disposable environments without external data. A real live deployment requires current account-specific entitlement/usage evidence and the owner's separate actual authorization. No business data/secrets, new capability toggles, protected owner credentials, PC changes, billing changes, or production Worker modifications are authorized by this research.
