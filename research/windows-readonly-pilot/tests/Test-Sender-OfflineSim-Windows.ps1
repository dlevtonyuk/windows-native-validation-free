# Disposable GitHub-hosted Windows VM ONLY. Never sends network traffic.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if(-not $env:RUNNER_TEMP -or -not $env:CI){throw 'DISPOSABLE_GITHUB_RUNNER_REQUIRED'}
$originalAppData=$env:LOCALAPPDATA
$isolated=Join-Path $env:RUNNER_TEMP ('cwfr-sender-local-mock-'+[Guid]::NewGuid().ToString('N'))
if(Test-Path -LiteralPath $isolated){throw 'ISOLATED_DIRECTORY_EXISTS'}
[void](New-Item -ItemType Directory -Path $isolated -ErrorAction Stop)
$env:LOCALAPPDATA=$isolated
try {
    $working=Join-Path $isolated 'source'
    [void](New-Item -ItemType Directory -Path $working -ErrorAction Stop)
    $inputDir=Join-Path $PSScriptRoot '..\windows'
    $collector=Join-Path $inputDir 'Collect-ReadOnlyAggregate.ps1'
    $prepare=Join-Path $inputDir 'Prepare-LocalEnrollment-NOT-RUN.ps1'
    $sender=Join-Path $inputDir 'Send-ReadOnlyAggregate-NOT-RUN.ps1'
    foreach($file in @($collector,$prepare)) {
        Copy-Item -LiteralPath $file -Destination $working -ErrorAction Stop
    }
    $enrollment=@(& (Join-Path $working 'Prepare-LocalEnrollment-NOT-RUN.ps1'))
    $digestLine=@($enrollment | Where-Object {$_ -like 'TOKEN_SHA256_PUBLIC_ENROLLMENT_DIGEST=*'})
    if($digestLine.Count -ne 1){throw 'ENROLLMENT_DIGEST_MISSING'}
    $expectedTokenDigest=$digestLine[0].Split('=')[1]
    $configPath=Join-Path $isolated 'CWFR\WindowsReadOnlyTelemetryPilot\config.json'
    $config=Get-Content -LiteralPath $configPath -Raw|ConvertFrom-Json
    $hostName='cwfr-windows-telemetry-staging.example.workers.dev' # Fake host. Never contacted.
    $config.endpoint='https://'+$hostName+'/v1/telemetry'
    [IO.File]::WriteAllText($configPath,($config|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
    $sha=[Security.Cryptography.SHA256]::Create()
    try {$pin=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($hostName))).Replace('-','').ToLowerInvariant()}
    finally{$sha.Dispose()}
    $src=[IO.File]::ReadAllText($sender)
    $blankPin='$PinnedWorkerHostSha256=' + "''"
    $pinned='$PinnedWorkerHostSha256=' + "'"+$pin+"'"
    if($src.Split($blankPin).Count -ne 2){throw 'ORIGINAL_SENDER_PIN_NOT_BLANK'}
    if($src.Split('Invoke-WebRequest -Uri').Count -ne 2){throw 'ORIGINAL_SENDER_TRANSPORT_UNEXPECTED'}
    # The temporary copy substitutes the transport symbol, not its real implementation.
    # If our mock is absent, the test fails closed: it has no Invoke-WebRequest call.
    $safeSource=$src.Replace($blankPin,$pinned).Replace('Invoke-WebRequest -Uri','Invoke-CWFRMockedWebRequest -Uri')
    $tempSender=Join-Path $working 'Send-ReadOnlyAggregate-NOT-RUN.ps1'
    [IO.File]::WriteAllText($tempSender,$safeSource,[Text.UTF8Encoding]::new($false))
    $global:CWFRMockRequestCount=0
    $global:CWFRMockDigest=$expectedTokenDigest
    function global:Invoke-CWFRMockedWebRequest {
        [CmdletBinding()]
        param([uri]$Uri,[string]$Method,[hashtable]$Headers,[string]$ContentType,[string]$Body,
              [switch]$UseBasicParsing,[int]$TimeoutSec,[int]$MaximumRedirection)
        if($Uri.DnsSafeHost -cne 'cwfr-windows-telemetry-staging.example.workers.dev' -or
           $Uri.AbsolutePath -cne '/v1/telemetry' -or $Uri.Scheme -cne 'https' -or
           $Method -cne 'POST' -or $TimeoutSec -gt 15 -or $MaximumRedirection -ne 0) {
            throw 'MOCK_TRANSPORT_CONTRACT_MISMATCH'
        }
        if($ContentType -cne 'application/json'){throw 'MOCK_CONTENT_TYPE_MISMATCH'}
        $rawToken=$Headers['Authorization'].Substring(7)
        $hasher=[Security.Cryptography.SHA256]::Create()
        try {$d=[BitConverter]::ToString($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($rawToken))).Replace('-','').ToLowerInvariant()}
        finally {$hasher.Dispose()}
        if($d -cne $global:CWFRMockDigest){throw 'MOCK_CREDENTIAL_MISMATCH'}
        $json=$Body|ConvertFrom-Json
        if($json.schema -ne 1 -or $json.evidence_kind -ne 'aggregate_windows_readonly' -or
           $json.cpu_used_pct -lt 0 -or $json.cpu_used_pct -gt 100 -or
           $json.ram_used_pct -lt 0 -or $json.ram_used_pct -gt 100 -or
           $json.sample_id -notmatch '^[a-f0-9-]{36}$' -or
           $json.PSObject.Properties.Name -contains 'top_memory'){
            throw 'MOCK_PAYLOAD_INVALID'
        }
        $global:CWFRMockRequestCount++
        return [pscustomobject]@{StatusCode=202}
    }
    $result=@(& $tempSender)
    if($global:CWFRMockRequestCount -ne 1 -or $result -notcontains 'READONLY_AGGREGATE_DELIVERED'){
        throw 'MOCK_SENDER_DID_NOT_DELIVER'
    }
    # A changed endpoint must be refused BEFORE the mocked outbound call.
    $config.endpoint='https://cwfr-windows-telemetry-staging.other.workers.dev/v1/telemetry'
    [IO.File]::WriteAllText($configPath,($config|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
    $failedClosed=$false
    try {& $tempSender | Out-Null}catch {if($_.Exception.Message -eq 'OWNER_PINNED_HOST_MISMATCH'){$failedClosed=$true}else{throw}}
    if(-not $failedClosed -or $global:CWFRMockRequestCount -ne 1){throw 'MOCK_WRONG_HOST_NOT_REJECTED'}
    Write-Output 'WINDOWS_SENDER_OFFLINE_HTTPS_CONTRACT_PASS'
}
finally {
    Remove-Item Function:\Invoke-CWFRMockedWebRequest -ErrorAction SilentlyContinue
    Remove-Variable CWFRMockRequestCount -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable CWFRMockDigest -Scope Global -ErrorAction SilentlyContinue
    $env:LOCALAPPDATA=$originalAppData
    Remove-Item -LiteralPath $isolated -Recurse -Force -ErrorAction Stop
}