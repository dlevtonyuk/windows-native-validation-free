$ErrorActionPreference='Stop'
if($env:RUNNER_OS -ne 'Windows' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'HOSTED_WINDOWS_ONLY'}
$task='ChatGPT-Lab-Runner-'+[guid]::NewGuid().ToString('N')
$folder=Join-Path $env:RUNNER_TEMP ('runner-task-'+[guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($folder)|Out-Null
$vbs=Join-Path $folder 'noop.vbs'
[IO.File]::WriteAllText($vbs,'Set shell = CreateObject("WScript.Shell")'+[Environment]::NewLine,
 (New-Object System.Text.UTF8Encoding($false)))
$registered=$false
try{
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name
 $action=New-ScheduledTaskAction -Execute (Join-Path $env:WINDIR 'System32\wscript.exe') -Argument ('"'+$vbs+'"')
 $trigger=New-ScheduledTaskTrigger -AtLogOn
 $principal=New-ScheduledTaskPrincipal -UserId $identity -LogonType Interactive -RunLevel Limited
 $settings=New-ScheduledTaskSettingsSet -Hidden -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero)
 Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger -Principal $principal -Settings $settings -ErrorAction Stop|Out-Null
 $registered=$true
 $got=Get-ScheduledTask -TaskName $task -ErrorAction Stop
 if($got.Actions.Count -ne 1 -or $got.Triggers.Count -ne 1){throw 'TASK_SHAPE_UNEXPECTED'}
 if($got.Principal.LogonType -ne 'Interactive'){throw 'NOT_INTERACTIVE_USER_TASK'}
 if(-not $got.Settings.Hidden){throw 'TASK_NOT_HIDDEN'}
 Write-Host 'HIDDEN_RUNNER_LOGON_TASK_NATIVE_PASSED'
}finally{
 if($registered){Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction Stop}
 Remove-Item -LiteralPath $folder -Force -Recurse -ErrorAction SilentlyContinue
}
