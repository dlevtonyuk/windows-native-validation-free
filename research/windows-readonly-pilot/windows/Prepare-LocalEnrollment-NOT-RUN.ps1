# OWNER-APPROVED EXECUTION REQUIRED. This script is NOT executed by ChatGPT.
# Makes only a per-user DPAPI credential and a pseudonymous enrollment digest.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows){throw 'WINDOWS_ONLY'}
$directory=Join-Path $env:LOCALAPPDATA 'CWFR\WindowsReadOnlyTelemetryPilot'
$configPath=Join-Path $directory 'config.json'
$secretPath=Join-Path $directory 'token.userdpapi'
if(Test-Path -LiteralPath $directory){throw 'PILOT_DIRECTORY_ALREADY_EXISTS_REFUSE_OVERWRITE'}
[void](New-Item -ItemType Directory -Path $directory -Force:$false)
$bytes=New-Object byte[] 32
$rng=[System.Security.Cryptography.RandomNumberGenerator]::Create()
try {$rng.GetBytes($bytes)}finally{$rng.Dispose()}
$token=([Convert]::ToBase64String($bytes)).TrimEnd('=').Replace('+','-').Replace('/','_')
$hashAlgo=[System.Security.Cryptography.SHA256]::Create()
try {$digest=[BitConverter]::ToString($hashAlgo.ComputeHash([Text.Encoding]::UTF8.GetBytes($token))).Replace('-','').ToLowerInvariant()}finally{$hashAlgo.Dispose()}
Add-Type -AssemblyName System.Security
$protected=[Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($token),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
[IO.File]::WriteAllBytes($secretPath,$protected)
$device=[Guid]::NewGuid().ToString('N')
# Endpoint left empty until Cloudflare owner explicitly authorizes and enables HTTPS ingress.
$config=[ordered]@{schema=1;device_id=$device;endpoint='';min_interval_seconds=60}
[IO.File]::WriteAllText($configPath,($config|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
[Array]::Clear($bytes,0,$bytes.Length)
# PUBLIC enrollment data only. NEVER display, copy or transmit raw token or DPAPI ciphertext.
Write-Output ('DEVICE_ID='+$device)
Write-Output ('TOKEN_SHA256_PUBLIC_ENROLLMENT_DIGEST='+$digest)
Write-Output 'ENROLLMENT_PREPARED_NO_DEVICE_ENROLLED_NO_TASK_CREATED'