# UAG owner-controlled private runner — RESEARCH ONLY

Goal: keep the existing Cloudflare account as the universal coordinator, with ONE owner-controlled private GitHub repository as an independent executor and future owner-release authority. NO new account or paid service is presumed, and NO business workflow is activated by this research.

## Essential security boundary

The connected ChatGPT GitHub installation currently has access to ALL repositories, including newly created private repositories. Before making the trusted repo, the owner must change its selection to ONLY the existing TWO approved repositories: dlevtonyuk/windows-native-validation-free and dlevtonyuk/windows-native-validation-lab. Both existing connections must remain working. Then the owner creates the new PRIVATE runner repo manually; do NOT install the ChatGPT app in it. Only a verified negative access test establishes separation. The connected Cloudflare app retains broad write permissions, so do NOT put owner secrets or business effects in assistant-editable Cloudflare code/D1.

## Files for one private owner-controlled repo

- foundation_read_only.mjs — exactly four fixed Cloudflare D1 SELECT requests; rejects unknown states; aggregate-only result.
- private_runner_main.mjs — safe entrypoint that logs only aggregate/sanitized status.
- owner_private_runner.yml — copy to private repo path .github/workflows/uag-owner-trusted-runner.yml. This is a template intentionally NOT installed in the public GitHub workflows folder.
- oidc_receipt.mjs — separate OFFLINE verifier of GitHub identity JWT whose signed audience binds the report hash; not wired to live runner or storage yet.

Private repository variables: UAG_CF_ACCOUNT_ID, UAG_CF_D1_DATABASE_ID. Owner-provisioned GitHub secret: UAG_CF_D1_READ_TOKEN, containing Cloudflare custom API token with only D1 Read for the existing account. No token or private data is to enter ChatGPT, assistant-editable Workers, public CI or public GitHub.

The template runner is hourly at minute :17 UTC, serial, with 3-minute job timeout. GitHub Free documents 2,000 included private standard-runner minutes per month. At 1 billed minute/run a 31-day month would use 744 minutes; at 3 billed minutes/run 2,232 exceeds the Free allowance. Owner MUST check actual account-wide usage and verify a cost fail-stop BEFORE turning on scheduling. GitHub scheduled runs may delay or skip at load, so this is not proof of payroll deadline reliability.

The current CLI and CI research did NOT use an owner-private repo or real GitHub OIDC JWT. Existing Ubuntu/Windows tests passing do not prove actual privacy boundary, real credentials, live private execution, business effect or owner acceptance.

## Explicit next gate

One consolidated owner-only action: (1) select and preserve both existing ChatGPT GitHub-connected repos; (2) create single private owner-controlled repo inaccessible to the assistant; (3) verify Github Actions budget; (4) install pinned, owner-reviewed template files; (5) provision narrowly scoped D1 Read token in private Actions Secrets and two IDs in Actions Variables; (6) manually run first protected probe; (7) have assistant independently check the Github app installation excludes owner-private repo, without attempting edits. Anything involving real provider data, approvals, changes, new paid resources, credential escalation or secret-bearing Cloudflare Workers needs further authorization.
