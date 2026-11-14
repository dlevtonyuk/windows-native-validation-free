# Disposable GitHub-hosted Windows VM ONLY. No real device or outbound requests.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if(-not $env:RUNNER_TEMP){throw 'DISPOSABLE_GITHUB_RUNNER_REQUIRED'}
$original=$env:LOCALAPPDATA
$unique=[guid]::NewGuid().ToString('N')
$isolated=Join-Path $env:RUNNER_TEMP ('cwfr-readonly-ci-'+$unique)
if(Test-Path -LiteralPath $isolated){throw 'ISOLATED_DIRECTORY_COLLISION'}
$created=$false
try {
    [void](New-Item -ItemType Directory -Path $isolated -ErrorAction Stop)
    $created=$true
    $env:LOCALAPPDATA=$isolated
    $root=Join-Path $PSScriptRoot '..\windows'
    $prepare=Join-Path $root 'Prepare-LocalEnrollment-NOT-RUN.ps1'
    $sender=Join-Path $root 'Send-ReadOnlyAggregate-NOT-RUN.ps1'
    $output=@(& $prepare)
    $deviceLine=@($output|Where-Object{$_ -like 'DEVICE_ID=*'})
    $hashLine=@($output|Where-Object{$_ -like 'TOKEN_SHA256_PUBLIC_ENROLLMENT_DIGEST=*'})
    if($deviceLine.Count -ne 1 -or $hashLine.Count -ne 1){throw 'BOOTSTRAP_OUTPUT_INCOMPLETE'}
    $device=([string]$deviceLine[0]).Split('=')[1]
    $hash=([string]$hashLine[0]).Split('=')[1]
    if($device -notmatch '^[a-f0-9]{32}$' -or $hash -notmatch '^[a-f0-9]{64}$'){throw 'PSEUDONYM_OR_DIGEST_INVALID'}
    $cfgPath=Join-Path $isolated 'CWFR\WindowsReadOnlyTelemetryPilot\config.json'
    $tokenPath=Join-Path $isolated 'CWFR\WindowsReadOnlyTelemetryPilot\token.userdpapi'
    if(-not (Test-Path -LiteralPath $tokenPath)){throw 'DPAPI_FILE_MISSING'}
    $cfg=Get-Content -LiteralPath $cfgPath -Raw|ConvertFrom-Json
    if($cfg.endpoint -ne '' -or $cfg.device_id -ne $device){throw 'ENROLLMENT_SHOULD_DEFAULT_TO_DISABLED'}
    $secret=[Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($tokenPath),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
    try {
        $h=[Security.Cryptography.SHA256]::Create()
        try {$actual=[BitConverter]::ToString($h.ComputeHash($secret)).Replace('-','').ToLowerInvariant()}
        finally {$h.Dispose()}
        if($actual -cne $hash){throw 'DPAPI_DIGEST_MISMATCH'}
    }finally {[Array]::Clear($secret,0,$secret.Length)}
    $cfg.endpoint='https://cwfr-windows-telemetry-staging.example.workers.dev/v1/telemetry'
    [IO.File]::WriteAllText($cfgPath,($cfg|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
    $failedClosed=$false
    try { & $sender }catch {
        if($_.Exception.Message -eq 'OWNER_PINNED_WORKER_HOST_REQUIRED'){$failedClosed=$true}
        else {throw 'UNEXPECTED_SENDER_FAILURE'}
    }
    if(-not $failedClosed){throw 'SENDER_FAILED_TO_ENFORCE_HOST_PIN'}
    Write-Output 'WINDOWS_NATIVE_DPAPI_AND_FAILCLOSED_SENDER_PASS'
}
finally {
    $env:LOCALAPPDATA=$original
    if($created){Remove-Item -LiteralPath $isolated -Recurse -Force -ErrorAction Stop}
}