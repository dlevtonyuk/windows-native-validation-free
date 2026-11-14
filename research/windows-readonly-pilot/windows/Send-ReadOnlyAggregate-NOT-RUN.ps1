# OWNER-APPROVED EXECUTION REQUIRED; separate cloud enrollment and endpoint activation first.
# A fail-closed, outbound-only Windows PowerShell sender. No arbitrary URLs or remote command execution.
[CmdletBinding()]
param([switch]$LocalSampleOnly)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$collector=Join-Path $PSScriptRoot 'Collect-ReadOnlyAggregate.ps1'
if(-not (Test-Path -LiteralPath $collector -PathType Leaf)){throw 'COLLECTOR_MISSING'}
if($LocalSampleOnly){ & $collector; return }
$folder=Join-Path $env:LOCALAPPDATA 'CWFR\WindowsReadOnlyTelemetryPilot'
$configPath=Join-Path $folder 'config.json'
$secretPath=Join-Path $folder 'token.userdpapi'
if(-not (Test-Path -LiteralPath $configPath -PathType Leaf) -or -not (Test-Path -LiteralPath $secretPath -PathType Leaf)){throw 'OWNER_ENROLLMENT_REQUIRED'}
$config=Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
if($config.schema -ne 1 -or $config.device_id -cnotmatch '^[a-f0-9]{32}$' -or $config.min_interval_seconds -lt 60){throw 'UNEXPECTED_OWNER_CONFIGURATION'}
$uri=$null
try {$uri=[Uri]$config.endpoint}catch{throw 'OWNER_ENDPOINT_NOT_ACTIVATED'}
if($uri.Scheme -cne 'https' -or $uri.Host -cnotmatch '^cwfr-windows-telemetry-staging\.[a-z0-9-]+\.workers\.dev$' -or $uri.AbsolutePath -cne '/v1/telemetry' -or $uri.Query -ne '' -or $uri.Fragment -ne '' -or $uri.UserInfo -ne '' -or $uri.Port -ne 443){throw 'ENDPOINT_OUT_OF_SCOPE'}

# Deployment-specific owner pin. Intentionally INERT in all distributed and public research code.
# Only owner-approved enrollment may replace the empty value with the SHA-256 of the
# exact, separately verified Cloudflare Worker DNS hostname (lowercase ASCII).
# The pin lives in the audited sender source, never in editable config.json.
$PinnedWorkerHostSha256=''
if($PinnedWorkerHostSha256 -cnotmatch '^[0-9a-f]{64}$'){throw 'OWNER_PINNED_WORKER_HOST_REQUIRED'}
$hasher=[Security.Cryptography.SHA256]::Create()
try { $hostDigest=([BitConverter]::ToString($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($uri.DnsSafeHost.ToLowerInvariant())))).Replace('-','').ToLowerInvariant() }
finally { $hasher.Dispose() }
if($hostDigest -cne $PinnedWorkerHostSha256){throw 'OWNER_PINNED_HOST_MISMATCH'}
Add-Type -AssemblyName System.Security
$encrypted=[IO.File]::ReadAllBytes($secretPath)
$plaintext=[Security.Cryptography.ProtectedData]::Unprotect($encrypted,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
$token=[Text.Encoding]::UTF8.GetString($plaintext)
[Array]::Clear($plaintext,0,$plaintext.Length)
if($token -cnotmatch '^[A-Za-z0-9_-]{43}$'){throw 'INVALID_LOCAL_TOKEN'}
$json=& $collector
$record=$json | ConvertFrom-Json
if($record.schema -ne 1 -or $record.evidence_kind -cne 'aggregate_windows_readonly'){throw 'COLLECTOR_SCHEMA_REJECTED'}
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
$headers=@{'Authorization'=('Bearer '+$token);'X-Device-Id'=$config.device_id}
try {
  $response=Invoke-WebRequest -Uri $uri.AbsoluteUri -Method POST -Headers $headers -ContentType 'application/json' -Body $json -UseBasicParsing -TimeoutSec 15 -MaximumRedirection 0 -ErrorAction Stop
  if([int]$response.StatusCode -notin @(200,202)){throw 'INGEST_REJECTED'}
  Write-Output 'READONLY_AGGREGATE_DELIVERED'
}catch{ throw 'READONLY_INGEST_UNAVAILABLE' }
finally {$token=$null;$headers.Clear()}