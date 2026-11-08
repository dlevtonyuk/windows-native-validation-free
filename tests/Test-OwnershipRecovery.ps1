$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'NOT_HOSTED_WINDOWS_RUNNER'}
$dir=Join-Path $env:RUNNER_TEMP ('owner-lab-'+[guid]::NewGuid().ToString('N'))
New-Item -Path $dir -ItemType Directory | Out-Null
$file=Join-Path $dir 'trace-ownership.json'
function Save-Owner([bool]$wmi,[bool]$wpr,[string]$session){
 [pscustomobject]@{version=1;wmi=$wmi;wpr=$wpr;session=$session}|ConvertTo-Json -Compress|Set-Content -LiteralPath $file -Encoding UTF8
}
function Restore-Owned{
 if(-not(Test-Path $file)){return 'NOTHING'}
 $record=Get-Content $file -Raw|ConvertFrom-Json
 if($record.session -ne 'ChatGPTWindowsNativeLab'){throw 'FOREIGN_SESSION'}
 if($record.wmi){Write-Host 'SIMULATED_WMI_RESTORATION'}
 if($record.wpr){Write-Host 'SIMULATED_WPR_CLEANUP'}
 Remove-Item $file -Force
 return 'CLEARED'
}
try{
 Save-Owner $false $false 'ChatGPTWindowsNativeLab'
 if((Restore-Owned) -ne 'CLEARED'){throw 'EMPTY_OWNER_CLEANUP_FAILED'}
 Save-Owner $true $true 'ForeignTrace'
 $rejected=$false
 try{Restore-Owned|Out-Null}catch{$rejected=$true}
 if(-not $rejected -or -not(Test-Path $file)){throw 'FOREIGN_TRACE_MODIFIED'}
 Save-Owner $true $true 'ChatGPTWindowsNativeLab'
 if((Restore-Owned) -ne 'CLEARED'){throw 'OWNED_TRACE_RECORD_NOT_CLEARED'}
 if((Restore-Owned) -ne 'NOTHING'){throw 'RESTORE_NOT_IDEMPOTENT'}
 Write-Host 'OWNERSHIP_RECOVERY_SIMULATION_PASSED'
}finally{Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue}