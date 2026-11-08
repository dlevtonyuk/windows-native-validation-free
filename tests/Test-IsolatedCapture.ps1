# Tests isolated native trace start-stop and failure recovery only on a GitHub-hosted Windows VM.
$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {throw 'HOSTED_WINDOWS_REQUIRED'}
$source=Join-Path $PSScriptRoot 'Invoke-IsolatedCapture.ps1'
$t=$null;$errors=$null
[System.Management.Automation.Language.Parser]::ParseFile($source,[ref]$t,[ref]$errors)|Out-Null
if ($errors.Count -gt 0) { throw ('CAPTURE_CONTROLLER_PARSE_ERROR: '+$errors[0].Message) }
Write-Host 'CAPTURE_CONTROLLER_PARSER_PASSED'
$root=Join-Path $env:RUNNER_TEMP ('capturev6-'+[guid]::NewGuid().ToString('N'))
try {
    & $source -Mode Probe -Root $root
    Write-Host 'CAPTURE_PROBE_PASSED'
    $caught=$false
    try { & $source -Mode FaultAfterWmi -Root $root } catch {
        if ($_.Exception.Message -match 'SIMULATED_FAILURE_AFTER_WMI_ENABLE') {$caught=$true}
        else { throw }
    }
    if (-not $caught) {throw 'INJECTED_FAULT_DID_NOT_TRIGGER'}
    & $source -Mode VerifyState -Root $root
    Write-Host 'FAULT_INJECTION_CLEANUP_PASSED'
    & $source -Mode Capture -Root $root -Seconds 3
    & $source -Mode VerifyState -Root $root
    Write-Host 'BOUNDED_REAL_TRACE_CAPTURE_PASSED'
    $ownerFile=Join-Path $root 'trace-ownership.json'
    if (Test-Path $ownerFile) {throw 'PENDING_OWNER_AFTER_LIVE_CAPTURE'}
    $ps=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $p=Start-Process -FilePath $ps -ArgumentList @(
        '-NoProfile','-NonInteractive','-File',('"'+$source+'"'),
        '-Mode','SyntheticCrash','-Root',('"'+$root+'"')) -Wait -PassThru -NoNewWindow
    if ($p.ExitCode -eq 0) {throw 'SYNTHETIC_CRASH_EXITED_SUCCESS_UNEXPECTEDLY'}
    if (-not (Test-Path $ownerFile)) {throw 'SIMULATED_CRASH_DID_NOT_LEAVE_OWNER'}
    & $source -Mode Recover -Root $root
    & $source -Mode VerifyState -Root $root
    Write-Host 'ABRUPT_EXIT_OWNERSHIP_RECOVERY_PASSED'
    Write-Host 'ISOLATED_CAPTURE_FULL_SUITE_PASSED'
} finally {
    if (Test-Path $root) {
        $ownerFile=Join-Path $root 'trace-ownership.json'
        if (-not (Test-Path $ownerFile)) {
            Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
        } else { Write-Host 'PENDING_OWNER_REQUIRES_REVIEW_NO_DIRECTORY_REMOVAL' }
    }
}
