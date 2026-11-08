$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'NOT_HOSTED_WINDOWS_RUNNER'}
if($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5){throw 'POWERSHELL_5_1_REQUIRED'}
$dir=Join-Path $env:RUNNER_TEMP ('win-lab-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $dir | Out-Null
$taskName='ChatGPT-Lab-'+[guid]::NewGuid().ToString('N')
$created=$false
function Assert([bool]$valid,[string]$message){if(-not $valid){throw "FAIL: $message"};Write-Host "PASS: $message"}
function RunBounded([string]$exe,[string]$commandArguments,[int]$timeoutMs){
 $p=New-Object Diagnostics.Process
 $p.StartInfo.FileName=$exe;$p.StartInfo.Arguments=$commandArguments
 $p.StartInfo.UseShellExecute=$false;$p.StartInfo.CreateNoWindow=$true
 $p.StartInfo.RedirectStandardOutput=$true;$p.StartInfo.RedirectStandardError=$true
 try{
  if(-not $p.Start()){throw 'START_FAILED'}
  $finished=$p.WaitForExit($timeoutMs)
  if(-not $finished){$p.Kill();if(-not $p.WaitForExit(5000)){throw 'KILL_NOT_VERIFIED'}}
  $exit=$p.ExitCode;$stdout=$p.StandardOutput.ReadToEnd();$stderr=$p.StandardError.ReadToEnd()
  return [pscustomobject]@{TimedOut=(-not $finished);Exit=$exit;Stdout=$stdout;Stderr=$stderr}
 }finally{$p.Dispose()}
}
try{
 Write-Host 'WINDOWS_NATIVE_LAB_STARTED'
 $ps=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
 Assert (Test-Path $ps) 'Windows PowerShell executable'
 $py=(Get-Command python.exe -ErrorAction Stop).Source
 $slowFile=Join-Path $dir 'sleeper.py'
 [IO.File]::WriteAllText($slowFile,'import time'+[Environment]::NewLine+'time.sleep(10)'+[Environment]::NewLine)
 $slow=RunBounded $py ('"'+$slowFile+'"') 1200
 Write-Host ('SLOW_TEST_RESULT timeout='+$slow.TimedOut+' exit='+$slow.Exit+' stdout='+($slow.Stdout -replace '[\\r\\n]+',' ')+' stderr='+($slow.Stderr -replace '[\\r\\n]+',' '))
 Assert $slow.TimedOut 'Timed-out subprocess terminated'
 $pyFile=Join-Path $dir 'check.py'
 [IO.File]::WriteAllText($pyFile,'print("ok")'+[Environment]::NewLine)
 $syntax=RunBounded $py ('-m py_compile "'+$pyFile+'"') 10000
 Assert (-not $syntax.TimedOut -and $syntax.Exit -eq 0) 'Python compile without nested quoting'
 $diskSource='$drive=Get-PSDrive -Name C -ErrorAction Stop; if($drive.Free -lt 0){throw "UNEXPECTED_DISK_VALUE"}; Write-Output $drive.Free'
 $diskEncoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($diskSource))
 $disk=RunBounded $ps ('-NoProfile -NonInteractive -EncodedCommand '+$diskEncoded) 12000
 Assert (-not $disk.TimedOut -and $disk.Exit -eq 0 -and $disk.Stdout.Trim() -match '^\\d+ $lock=Join-Path $dir 'guard.lock'
 $first=[IO.File]::Open($lock,'OpenOrCreate','ReadWrite','None')
 try{
  $blocked=$false
  try{$second=[IO.File]::Open($lock,'Open','ReadWrite','None');$second.Dispose()}catch [IO.IOException]{$blocked=$true}
  Assert $blocked 'Exclusive lock prevents overlapping captures'
 }finally{$first.Dispose()}
 $reopened=[IO.File]::Open($lock,'Open','ReadWrite','None');$reopened.Dispose()
 Assert $true 'Capture lock released'
 $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
 $safeExe=[Security.SecurityElement]::Escape($ps)
 $xml=@"
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
<Triggers><TimeTrigger><StartBoundary>2099-01-01T00:00:00</StartBoundary><Enabled>false</Enabled>
<Repetition><Interval>PT2M</Interval></Repetition></TimeTrigger></Triggers>
<Principals><Principal id="P"><UserId>$sid</UserId><LogonType>InteractiveToken</LogonType>
<RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
<Settings><Enabled>false</Enabled><ExecutionTimeLimit>PT1M</ExecutionTimeLimit>
<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy></Settings>
<Actions Context="P"><Exec><Command>$safeExe</Command>
<Arguments>-NoProfile -NonInteractive -Command exit 0</Arguments></Exec></Actions>
</Task>
"@
 [xml]$parsed=$xml
 Assert ($null -ne $parsed.Task) 'Task XML parses'
 Register-ScheduledTask -TaskName $taskName -Xml $xml -ErrorAction Stop | Out-Null
 $created=$true
 $task=Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
 Assert ([string]$task.State -eq 'Disabled') 'Fixture task disabled'
 $exported=[xml](Export-ScheduledTask -TaskName $taskName)
 $mgr=New-Object System.Xml.XmlNamespaceManager($exported.NameTable)
 $mgr.AddNamespace('t','http://schemas.microsoft.com/windows/2004/02/mit/task')
 $interval=$exported.SelectSingleNode('//t:TimeTrigger/t:Repetition/t:Interval',$mgr)
 Assert ($null -ne $interval -and $interval.InnerText -eq 'PT2M') 'Task Scheduler repetition preserved'
 $wmi=RunBounded (Join-Path $env:WINDIR 'System32\wevtutil.exe') 'gl Microsoft-Windows-WMI-Activity/Trace' 12000
 Assert (-not $wmi.TimedOut -and $wmi.Exit -eq 0) 'Bounded read-only WMI metadata'
 Write-Host 'WMI_TRACE_UNMODIFIED=true'
 $wpr=Get-Command wpr.exe -ErrorAction SilentlyContinue
 if($wpr){
  $status=RunBounded $wpr.Source '-status -instancename ChatGPTWindowsNativeLab' 12000
  Assert (-not $status.TimedOut) 'WPR status bounded'
  Write-Host ('WPR_STATUS_EXIT='+$status.Exit)
 }else{Write-Host 'WPR_NOT_AVAILABLE'}
 Write-Host 'WPR_CAPTURE_TESTED=false'
 Write-Host 'WINDOWS_NATIVE_LAB_PASSED'
}finally{
 if($created){
  Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
  Assert ($null -eq (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) 'Test task removed'
 }
 Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
}) 'Bounded C drive free-space query'
 $metaSource='$m=Get-WinEvent -ListLog "Microsoft-Windows-WMI-Activity/Trace" -Force -ErrorAction Stop; Write-Output ("enabled="+$m.IsEnabled+";size="+$m.MaximumSizeInBytes+";mode="+$m.LogMode)'
 $metaEncoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($metaSource))
 $meta=RunBounded $ps ('-NoProfile -NonInteractive -EncodedCommand '+$metaEncoded) 15000
 Write-Host ('WMI_METADATA_TEST exit='+$meta.Exit+' timeout='+$meta.TimedOut+' stdout='+($meta.Stdout.Trim() -replace '[\\r\\n]+',' ')+' stderr='+($meta.Stderr.Trim() -replace '[\\r\\n]+',' '))
 Assert (-not $meta.TimedOut -and $meta.Exit -eq 0 -and $meta.Stdout -match 'enabled=(True|False);size=\\d+;mode=') 'Bounded WMI Get-WinEvent trace metadata'
 $lock=Join-Path $dir 'guard.lock'
 $first=[IO.File]::Open($lock,'OpenOrCreate','ReadWrite','None')
 try{
  $blocked=$false
  try{$second=[IO.File]::Open($lock,'Open','ReadWrite','None');$second.Dispose()}catch [IO.IOException]{$blocked=$true}
  Assert $blocked 'Exclusive lock prevents overlapping captures'
 }finally{$first.Dispose()}
 $reopened=[IO.File]::Open($lock,'Open','ReadWrite','None');$reopened.Dispose()
 Assert $true 'Capture lock released'
 $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
 $safeExe=[Security.SecurityElement]::Escape($ps)
 $xml=@"
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
<Triggers><TimeTrigger><StartBoundary>2099-01-01T00:00:00</StartBoundary><Enabled>false</Enabled>
<Repetition><Interval>PT2M</Interval></Repetition></TimeTrigger></Triggers>
<Principals><Principal id="P"><UserId>$sid</UserId><LogonType>InteractiveToken</LogonType>
<RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
<Settings><Enabled>false</Enabled><ExecutionTimeLimit>PT1M</ExecutionTimeLimit>
<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy></Settings>
<Actions Context="P"><Exec><Command>$safeExe</Command>
<Arguments>-NoProfile -NonInteractive -Command exit 0</Arguments></Exec></Actions>
</Task>
"@
 [xml]$parsed=$xml
 Assert ($null -ne $parsed.Task) 'Task XML parses'
 Register-ScheduledTask -TaskName $taskName -Xml $xml -ErrorAction Stop | Out-Null
 $created=$true
 $task=Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
 Assert ([string]$task.State -eq 'Disabled') 'Fixture task disabled'
 $exported=[xml](Export-ScheduledTask -TaskName $taskName)
 $mgr=New-Object System.Xml.XmlNamespaceManager($exported.NameTable)
 $mgr.AddNamespace('t','http://schemas.microsoft.com/windows/2004/02/mit/task')
 $interval=$exported.SelectSingleNode('//t:TimeTrigger/t:Repetition/t:Interval',$mgr)
 Assert ($null -ne $interval -and $interval.InnerText -eq 'PT2M') 'Task Scheduler repetition preserved'
 $wmi=RunBounded (Join-Path $env:WINDIR 'System32\wevtutil.exe') 'gl Microsoft-Windows-WMI-Activity/Trace' 12000
 Assert (-not $wmi.TimedOut -and $wmi.Exit -eq 0) 'Bounded read-only WMI metadata'
 Write-Host 'WMI_TRACE_UNMODIFIED=true'
 $wpr=Get-Command wpr.exe -ErrorAction SilentlyContinue
 if($wpr){
  $status=RunBounded $wpr.Source '-status -instancename ChatGPTWindowsNativeLab' 12000
  Assert (-not $status.TimedOut) 'WPR status bounded'
  Write-Host ('WPR_STATUS_EXIT='+$status.Exit)
 }else{Write-Host 'WPR_NOT_AVAILABLE'}
 Write-Host 'WPR_CAPTURE_TESTED=false'
 Write-Host 'WINDOWS_NATIVE_LAB_PASSED'
}finally{
 if($created){
  Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
  Assert ($null -eq (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) 'Test task removed'
 }
 Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
}