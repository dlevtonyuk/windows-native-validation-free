# Generic, ephemeral Windows diagnostic trace controller. No production paths or data.
[CmdletBinding()]
param(
    [ValidateSet('Probe','Capture','Recover','FaultAfterWmi','SyntheticCrash','VerifyState')]
    [string]$Mode = 'Probe',
    [Parameter(Mandatory=$true)][string]$Root,
    [ValidateRange(1,10)][int]$Seconds = 3
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted') { throw 'HOSTED_WINDOWS_ONLY' }
if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5) {
    throw 'WINDOWS_POWERSHELL_5_1_ONLY'
}
$absRoot=[IO.Path]::GetFullPath($Root)
$tempRoot=[IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\')+'\'
if (-not $absRoot.StartsWith($tempRoot,[StringComparison]::OrdinalIgnoreCase)) {
    throw 'ROOT_MUST_BE_UNDER_EPHEMERAL_RUNNER_TEMP'
}
[IO.Directory]::CreateDirectory($absRoot) | Out-Null
$lockPath=Join-Path $absRoot 'controller.lock'
$ownerPath=Join-Path $absRoot 'trace-ownership.json'
$channel='Microsoft-Windows-WMI-Activity/Trace'
$wpr=(Get-Command wpr.exe -ErrorAction Stop).Source
$wevt=Join-Path $env:WINDIR 'System32\wevtutil.exe'
$pwsh=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$utf8=New-Object System.Text.UTF8Encoding($false)
$lock=$null

function RunBounded([string]$exe,[string]$commandArguments,[int]$limitMs) {
    if ($limitMs -lt 100 -or $limitMs -gt 90000) {throw 'INVALID_TIMEOUT'}
    $p=New-Object System.Diagnostics.Process
    $p.StartInfo.FileName=$exe
    $p.StartInfo.Arguments=$commandArguments
    $p.StartInfo.UseShellExecute=$false
    $p.StartInfo.CreateNoWindow=$true
    $p.StartInfo.RedirectStandardOutput=$true
    $p.StartInfo.RedirectStandardError=$true
    try {
        if (-not $p.Start()) {throw 'FAILED_TO_START_CHILD'}
        $outTask=$p.StandardOutput.ReadToEndAsync()
        $errTask=$p.StandardError.ReadToEndAsync()
        $done=$p.WaitForExit($limitMs)
        if (-not $done) {
            try { $p.Kill() } catch { }
            if (-not $p.WaitForExit(5000)) {throw 'CHILD_UNKILLABLE'}
        }
        $text=[string]$outTask.Result+[Environment]::NewLine+[string]$errTask.Result
        return [pscustomobject]@{TimedOut=(-not $done); Exit=[int]$p.ExitCode; Text=$text}
    } finally { $p.Dispose() }
}
function RequireOK($result,[string]$where) {
    if ($result.TimedOut) {throw ($where+'_TIMEOUT')}
    if ($result.Exit -ne 0) {throw ($where+'_EXIT_'+$result.Exit+':'+$result.Text.Substring(0,[Math]::Min(200,$result.Text.Length)))}
}
function Persist($state) {
    $tmp=$ownerPath+'.new-'+[guid]::NewGuid().ToString('N')
    [IO.File]::WriteAllText($tmp,($state|ConvertTo-Json -Depth 5 -Compress),$utf8)
    if ([IO.File]::Exists($ownerPath)) {
        $backup=$ownerPath+'.backup-'+[guid]::NewGuid().ToString('N')
        [IO.File]::Replace($tmp,$ownerPath,$backup)
        if ([IO.File]::Exists($backup)) { [IO.File]::Delete($backup) }
    } else { [IO.File]::Move($tmp,$ownerPath) }
}
function ReadOwner() {
    if (-not (Test-Path -LiteralPath $ownerPath)) {return $null}
    $o=Get-Content -LiteralPath $ownerPath -Raw -Encoding UTF8|ConvertFrom-Json
    if ($null -eq $o -or $o.schema -ne 1 -or $o.session -notmatch '^OpenAILab[A-F0-9]{12}$') {
        throw 'UNKNOWN_OWNER_RECORD_FAIL_CLOSED'
    }
    return $o
}
function ChannelSettings() {
    $q=RunBounded $wevt ('gl '+$channel) 12000
    RequireOK $q 'READ_CHANNEL'
    $e=[regex]::Match($q.Text,'(?im)^\s*enabled:\s*(true|false)\s*$')
    $r=[regex]::Match($q.Text,'(?im)^\s*retention:\s*(true|false)\s*$')
    $m=[regex]::Match($q.Text,'(?im)^\s*maxSize:\s*(\d+)\s*$')
    if (-not $e.Success -or -not $r.Success -or -not $m.Success) {throw 'UNRECOGNIZED_CHANNEL_CONFIGURATION'}
    return [pscustomobject]@{Enabled=($e.Groups[1].Value -eq 'true'); Retention=($r.Groups[1].Value -eq 'true'); MaxSize=[long]$m.Groups[1].Value}
}
function NamedStatus([string]$session) {
    $r=RunBounded $wpr ('-status -instancename '+$session) 12000
    if ($r.TimedOut) {throw 'NAMED_WPR_STATUS_TIMEOUT'}
    if ($r.Text -match '(?i)recording is in progress') {return 'ACTIVE'}
    if ($r.Text -match '(?i)(there are no trace profiles running|not recording|no recording|no trace profiles running)') {return 'INACTIVE'}
    throw ('UNKNOWN_WPR_STATUS_FAIL_CLOSED: '+$r.Text.Substring(0,[Math]::Min(200,$r.Text.Length)))
}
function RecoverOwned() {
    $o=ReadOwner
    if ($null -eq $o) {return 'NONE'}
    $errors=@()
    if ($o.wpr_may_have_started) {
        try {
            $s=NamedStatus ([string]$o.session)
            if ($s -eq 'ACTIVE') {
                $etl=Join-Path $absRoot ('labtrace-'+$o.session+'.etl')
                $q=RunBounded $wpr ('-stop "'+$etl+'" -skipPdbGen -instancename '+$o.session) 60000
                if ($q.TimedOut -or $q.Exit -ne 0) {
                    $cancel=RunBounded $wpr ('-cancel -instancename '+$o.session) 20000
                    RequireOK $cancel 'OWNED_WPR_CANCEL'
                }
            }
            if ((NamedStatus ([string]$o.session)) -ne 'INACTIVE') { throw 'OWNED_WPR_SESSION_STILL_ACTIVE' }
            $o.wpr_may_have_started=$false
            Persist $o
        } catch { $errors+=('WPR_RESTORE:'+($_.Exception.Message)) }
    }
    if ($o.wmi_restore_needed) {
        try {
            if ($o.original_enabled) {throw 'PREEXISTING_ENABLED_CHANNEL_REFUSE_RESTORE'}
            $q=RunBounded $wevt ('sl '+$channel+' /e:false') 15000
            RequireOK $q 'WMI_DISABLE'
            $ret=if ($o.original_retention) {'true'} else {'false'}
            $q=RunBounded $wevt ('sl '+$channel+' /rt:'+$ret+' /ms:'+$o.original_max_size) 15000
            RequireOK $q 'WMI_RESTORE_CONFIG'
            $actual=ChannelSettings
            if ($actual.Enabled -or $actual.Retention -ne $o.original_retention -or
                $actual.MaxSize -ne $o.original_max_size) {throw 'WMI_RESTORE_VERIFY_FAILED'}
            $o.wmi_restore_needed=$false
            Persist $o
        } catch { $errors+=('WMI_RESTORE:'+($_.Exception.Message)) }
    }
    if ($errors.Count -gt 0) {throw ('OWNERSHIP_RECOVERY_INCOMPLETE '+($errors -join ';'))}
    if ($o.wpr_may_have_started -or $o.wmi_restore_needed) {throw 'OWNER_STILL_PENDING'}
    Remove-Item -LiteralPath $ownerPath -Force
    return 'CLEARED'
}
try {
    try { $lock=[IO.File]::Open($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None) }
    catch [IO.IOException] {throw 'ANOTHER_CAPTURE_ACTIVE'}
    $status=RecoverOwned
    Write-Host ('PRIOR_OWNERSHIP_RECOVERY='+$status)
    if ($Mode -eq 'Recover') {
        Write-Host 'TRACE_RECOVERY_PASSED'
        return
    }
    if ($Mode -eq 'VerifyState') {
        if (Test-Path $ownerPath) {throw 'OWNER_FILE_STILL_PRESENT'}
        $c=ChannelSettings
        Write-Host ('CHANNEL_ENABLED='+$c.Enabled+';CHANNEL_RETENTION='+$c.Retention+';CHANNEL_SIZE='+$c.MaxSize)
        Write-Host 'OWNERSHIP_VERIFICATION_PASSED'
        return
    }
    $baseline=ChannelSettings
    $probe='Get-PSDrive -Name C -ErrorAction Stop | Select-Object -ExpandProperty Free'
    $enc=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($probe))
    $disk=RunBounded $pwsh ('-NoProfile -NonInteractive -EncodedCommand '+$enc) 12000
    RequireOK $disk 'BOUNDED_DISK_QUERY'
    Write-Host ('DISK_QUERY_PASSED='+$disk.Text.Trim())
    $named='OpenAILab'+([guid]::NewGuid().ToString('N').Substring(0,12).ToUpperInvariant())
    $probeState=NamedStatus $named
    if ($probeState -ne 'INACTIVE') {throw 'WPR_INSTANCE_NOT_AVAILABLE'}
    Write-Host ('NAMED_WPR_PROBE_PASSED='+$probeState)
    if ($Mode -eq 'Probe') {Write-Host 'ISOLATED_CAPTURE_PROBE_PASSED';return}
    if ($baseline.Enabled) {throw 'PREEXISTING_WMI_TRACE_ENABLED_REFUSE_CAPTURE'}
    $owner=[pscustomobject]@{
        schema=1;session=$named;original_enabled=$baseline.Enabled;
        original_retention=$baseline.Retention;original_max_size=$baseline.MaxSize;
        wmi_restore_needed=$true;wpr_may_have_started=$false;
        started_utc=[DateTimeOffset]::UtcNow.ToString('o')
    }
    Persist $owner
    $q=RunBounded $wevt ('sl '+$channel+' /e:true /rt:true /ms:16777216 /q:true') 15000
    RequireOK $q 'ENABLE_WMI'
    Write-Host 'LAB_WMI_ENABLED'
    if ($Mode -eq 'FaultAfterWmi') {throw 'SIMULATED_FAILURE_AFTER_WMI_ENABLE'}
    if ($Mode -eq 'SyntheticCrash') {
        Write-Host 'SYNTHETIC_OWNER_PENDING_CREATED'
        [System.Diagnostics.Process]::GetCurrentProcess().Kill()
        return
    }
    $owner.wpr_may_have_started=$true
    Persist $owner
    $q=RunBounded $wpr ('-start CPU.light -instancename '+$named) 15000
    RequireOK $q 'OWNED_WPR_START'
    Write-Host 'LAB_NAMED_WPR_STARTED'
    Start-Sleep -Seconds $Seconds
    Write-Host 'LAB_TRACE_DURATION_COMPLETE'
}
finally {
    if ($null -ne $lock) {
        try {
            $cleanup=RecoverOwned
            Write-Host ('CLEANUP_RESULT='+$cleanup)
        } finally { $lock.Dispose() }
    }
}
if ($Mode -eq 'Capture') {Write-Host 'ISOLATED_LIVE_CAPTURE_PASSED'}
