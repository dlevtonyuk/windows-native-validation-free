[CmdletBinding()]
param([switch]$ProbeOnly)
$ErrorActionPreference='Stop'
if($env:RUNNER_OS -ne 'Windows' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'HOSTED_WINDOWS_LAB_ONLY'
}
if(-not [Environment]::Is64BitOperatingSystem){throw 'X64_OS_REQUIRED'}
$uri='https://api.github.com/repos/actions/runner/releases/latest'
$headers=@{'User-Agent'='Windows-Native-Validation-Free-Runner-Probe';'Accept'='application/vnd.github+json'}
$rel=Invoke-RestMethod -Uri $uri -Headers $headers -TimeoutSec 20 -ErrorAction Stop
$asset=@($rel.assets|Where-Object { $_.name -match '^actions-runner-win-x64-\d+\.\d+\.\d+\.zip$' })
if($asset.Count -ne 1){throw 'RUNNER_RELEASE_ASSET_NOT_UNIQUE'}
$asset=$asset[0]
if($asset.browser_download_url -notmatch '^https://github\.com/actions/runner/releases/download/v\d+\.\d+\.\d+/actions-runner-win-x64-\d+\.\d+\.\d+\.zip$'){
    throw 'UNEXPECTED_RUNNER_ASSET_URL'
}
if([string]$asset.digest -notmatch '^sha256:[0-9a-fA-F]{64}$'){
    throw 'RUNNER_DIGEST_UNAVAILABLE_FAIL_CLOSED'
}
Write-Host ('OFFICIAL_RUNNER_RELEASE='+$rel.tag_name)
Write-Host ('OFFICIAL_RUNNER_ASSET_SIZE='+$asset.size)
Write-Host 'OFFICIAL_RUNNER_ASSET_SHA256_AVAILABLE=true'
Write-Host 'RUNNER_RELEASE_METADATA_VERIFIED'
