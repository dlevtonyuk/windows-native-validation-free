# Generic no-subscription GitHub self-hosted Windows runner bootstrap.
# VerifyPackage runs only on disposable GitHub-hosted Windows VMs.
[CmdletBinding()]
param(
  [ValidateSet('Probe','VerifyPackage','Register')][string]$Mode='Probe',
  [string]$RepositoryUrl='https://github.com/example/example-private-repo',
  [string]$Label='private-windows-diagnostics',
  [string]$RunnerName='ChatGPT-Private-Windows-Executor'
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if($env:OS -ne 'Windows_NT') { throw 'WINDOWS_REQUIRED' }
if(-not [Environment]::Is64BitOperatingSystem){throw 'WIN_X64_REQUIRED'}
if($Mode -eq 'Register' -and $RepositoryUrl -notmatch '^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') {
  throw 'EXPECTED_PRIVATE_GITHUB_REPOSITORY_URL'
}
if($Label -notmatch '^[a-z][a-z0-9-]{5,48}$' -or $RunnerName -notmatch '^[A-Za-z0-9-]{5,64}$') {
  throw 'INVALID_RUNNER_LABEL_OR_NAME'
}
$headers=@{'User-Agent'='SafeWindowsRunnerBootstrap';'Accept'='application/vnd.github+json'}
$release=Invoke-RestMethod -Uri 'https://api.github.com/repos/actions/runner/releases/latest' -Headers $headers -TimeoutSec 25 -ErrorAction Stop
$matches=@($release.assets | Where-Object { $_.name -match '^actions-runner-win-x64-\d+\.\d+\.\d+\.zip$' })
if($matches.Count -ne 1){throw 'EXPECTED_ONE_WIN_X64_RELEASE_ASSET'}
$asset=$matches[0]
if($asset.browser_download_url -notmatch '^https://github\.com/actions/runner/releases/download/v\d+\.\d+\.\d+/actions-runner-win-x64-\d+\.\d+\.\d+\.zip$'){
  throw 'UNEXPECTED_DOWNLOAD_DOMAIN_OR_FILENAME'
}
if([string]$asset.digest -match '^sha256:([0-9a-fA-F]{64})$'){$sha=$Matches[1].ToLowerInvariant()}
else{throw 'RELEASE_SHA256_MISSING'}
Write-Host ('OFFICIAL_RUNNER_VERSION='+$release.tag_name)
Write-Host 'OFFICIAL_SHA256_AVAILABLE=true'
if($Mode -eq 'Probe'){Write-Host 'RUNNER_BOOTSTRAP_PREFLIGHT_PASSED';return}
if($Mode -eq 'VerifyPackage') {
  if($env:RUNNER_OS -ne 'Windows' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){
    throw 'PACKAGE_VERIFICATION_ONLY_ON_DISPOSABLE_GITHUB_WINDOWS'
  }
  $root=Join-Path $env:RUNNER_TEMP ('runner-pkg-'+[guid]::NewGuid().ToString('N'))
} else {
  # Install as the current non-elevated user, not SYSTEM or an administrator service.
  $root=Join-Path $env:LOCALAPPDATA 'ChatGPT-Private-Windows-Runner'
  if(Test-Path -LiteralPath $root){throw 'RUNNER_FOLDER_ALREADY_EXISTS_FAIL_CLOSED'}
  if(Get-ScheduledTask -TaskName 'ChatGPT Private Windows Runner - At Logon' -ErrorAction SilentlyContinue){
    throw 'RUNNER_TASK_ALREADY_EXISTS_FAIL_CLOSED'
  }
}
$zip=Join-Path $env:TEMP ('runner-win-x64-'+[guid]::NewGuid().ToString('N')+'.zip')
$folderCreated=$false
try {
  Invoke-WebRequest -UseBasicParsing -Uri ([string]$asset.browser_download_url) -OutFile $zip -TimeoutSec 240 -ErrorAction Stop
  $hash=(Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
  if($hash -ne $sha){throw 'RUNNER_PACKAGE_SHA256_MISMATCH'}
  Write-Host 'RUNNER_PACKAGE_SHA256_VERIFIED'
  [IO.Directory]::CreateDirectory($root)|Out-Null
  $folderCreated=$true
  Expand-Archive -LiteralPath $zip -DestinationPath $root -ErrorAction Stop
  $config=Join-Path $root 'config.cmd';$run=Join-Path $root 'run.cmd'
  if(-not(Test-Path -LiteralPath $config -PathType Leaf) -or -not(Test-Path -LiteralPath $run -PathType Leaf)){
    throw 'OFFICIAL_RUNNER_ARCHIVE_CONTENTS_MISSING'
  }
  Write-Host 'OFFICIAL_RUNNER_EXTRACTION_VERIFIED'
  if($Mode -eq 'VerifyPackage'){Write-Host 'DISPOSABLE_RUNNER_PACKAGE_TEST_PASSED';return}
  # Registration token is entered LOCALLY, never shared with ChatGPT or issue text.
  $secure=Read-Host 'Paste the time-limited GitHub runner registration token here' -AsSecureString
  if($secure.Length -lt 10){throw 'REGISTRATION_TOKEN_TOO_SHORT'}
  $ptr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
  try {
    $token=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    Push-Location $root
    try {
      & $config --unattended --url $RepositoryUrl --token $token --name $RunnerName --labels $Label --work '_work'
      if($LASTEXITCODE -ne 0){throw 'GITHUB_REGISTRATION_FAILED'}
    } finally {Pop-Location}
  } finally {
    $token=$null
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
  }
  Write-Host 'PRIVATE_REPOSITORY_RUNNER_REGISTERED'
  $launcher=Join-Path $root 'StartHidden.vbs'
  $quoted='"'+$run+'"'
  $vbs='Set shell = CreateObject("WScript.Shell")'+[Environment]::NewLine+
    'shell.Run "'+$quoted.Replace('"','""')+'", 0, False'+[Environment]::NewLine
  [IO.File]::WriteAllText($launcher,$vbs,(New-Object System.Text.UTF8Encoding($false)))
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name
  $action=New-ScheduledTaskAction -Execute (Join-Path $env:WINDIR 'System32\wscript.exe') -Argument ('"'+$launcher+'"')
  $trigger=New-ScheduledTaskTrigger -AtLogOn
  $principal=New-ScheduledTaskPrincipal -UserId $identity -LogonType Interactive -RunLevel LeastPrivilege
  $settings=New-ScheduledTaskSettingsSet -Hidden -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero)
  Register-ScheduledTask -TaskName 'ChatGPT Private Windows Runner - At Logon' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -ErrorAction Stop|Out-Null
  Start-ScheduledTask -TaskName 'ChatGPT Private Windows Runner - At Logon' -ErrorAction Stop
  Write-Host 'HIDDEN_AT_LOGON_RUNNER_TASK_INSTALLED_AND_STARTED'
  Write-Host 'VERIFY_REPOSITORY_RUNNER_WITH_PRIVATE_GITHUB_WORKFLOW'
} finally {
  Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
  if($Mode -eq 'VerifyPackage' -and $folderCreated){Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue}
}
