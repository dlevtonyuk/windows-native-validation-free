# Free Windows Native Validation

Public, **generic** Windows test fixtures only. This repository uses GitHub-hosted **standard Windows Server 2025** runners, which GitHub provides free for public repositories. It does **not** contain production scripts, telemetry, logs, credentials, or private project data.

## Scope
- Native Windows PowerShell 5.1 tests
- Native Task Scheduler XML validation using a **disabled, temporary task**
- Bounded process timeout tests and exclusive lock tests
- Read-only WMI/WPR metadata checks
- Simulated (not actual) trace ownership and recovery

The GitHub workflow runs automatically on relevant commits, with the job explicitly gated to **public repositories** and GitHub-hosted Windows. It does not run on or alter the user's PC.

**Limitations:** Passing these tests does not mean the old V5 sentinel is safe, nor does it prove any performance root cause. Production V4 continues unchanged. The historical V5 task remains disabled pending a separate, proven replacement.

## Safety
Do not publish customer data, private repository files outside the vetted generic fixture allowlist, production code, credentials, raw ETLs, diagnostics, or any personal identifiers here. Never use larger/paid runners or paid services.
