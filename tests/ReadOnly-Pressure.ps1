[CmdletBinding()]
param(
    [int[]]$SuspectPids=@(),
    [ValidateRange(10,100)][int]$MaxEvents=50,
    [string]$OutFile
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$now=[DateTimeOffset]::UtcNow.ToString('o')
$procs=@(Get-Process -ErrorAction Stop)
$memInfo=$null
try {
    $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $memInfo=[ordered]@{
        total_mb=[Math]::Round([double]$os.TotalVisibleMemorySize/1024,0)
        available_mb=[Math]::Round([double]$os.FreePhysicalMemory/1024,0)
        used_pct=[Math]::Round(100*(1-([double]$os.FreePhysicalMemory/[double]$os.TotalVisibleMemorySize)),1)
    }
} catch { $memInfo=[ordered]@{error='MEMORY_QUERY_UNAVAILABLE'} }
$topMemory=@($procs|Sort-Object WorkingSet64 -Descending |Select-Object -First 20|
    ForEach-Object { [ordered]@{name=$_.ProcessName;pid=[int]$_.Id;working_mb=[Math]::Round($_.WorkingSet64/1MB,1);private_mb=[Math]::Round($_.PrivateMemorySize64/1MB,1)} })
$topHandles=@($procs|Sort-Object HandleCount -Descending |Select-Object -First 15|
    ForEach-Object { [ordered]@{name=$_.ProcessName;pid=[int]$_.Id;handles=[int]$_.HandleCount;threads=[int]$_.Threads.Count} })
$suspectRows=@()
foreach($suspect in ($SuspectPids|Select-Object -Unique)) {
    if ($suspect -le 0) {continue}
    $proc=$procs|Where-Object {$_.Id -eq $suspect}|Select-Object -First 1
    $services=@()
    try {
        $services=@(Get-CimInstance Win32_Service -Filter ('ProcessId='+[int]$suspect) -ErrorAction Stop |
            Select-Object Name,DisplayName,State)
    } catch { }
    $suspectRows+= [ordered]@{
        pid=[int]$suspect
        process_name=if($proc){$proc.ProcessName}else{$null}
        process_present=($null -ne $proc)
        service_names=@($services|ForEach-Object {$_.Name})
        service_count=$services.Count
    }
}
$wmiErrors=@()
$wmiread='OK'
try {
    $evt=@(Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-WMI-Activity/Operational'; Id=5858
        StartTime=(Get-Date).AddMinutes(-20)
    } -MaxEvents $MaxEvents -ErrorAction Stop)
    $counts=@{}
    foreach($e in $evt) {
        $msg=[string]$e.Message
        $pid=if($msg -match 'ClientProcessId\s*=\s*(\d+)') {[int]$Matches[1]} else {0}
        $code=if($msg -match 'ResultCode\s*=\s*(0x[0-9A-Fa-f]+)') {$Matches[1]} else {'unknown'}
        $category=if($msg -match '(?i)MSFT_NetAdapterStatisticsSettingData') {'NET_ADAPTER_STATS'} else {'OTHER'}
        $key=[string]$pid+'|'+$code+'|'+$category
        if(-not $counts.ContainsKey($key)){$counts[$key]=0}
        $counts[$key]++
    }
    $wmiErrors=@($counts.Keys|Sort-Object|ForEach-Object{
        $parts=$_.Split('|')
        [ordered]@{client_pid=[int]$parts[0];result_code=$parts[1];category=$parts[2];count=[int]$counts[$_]}
    })
} catch { $wmiread='NO_RECENT_EVENTS_OR_PERMISSION' }
$result=[ordered]@{
    schema=1;utc=$now;ram=$memInfo;process_count=$procs.Count
    top_memory=$topMemory;top_handles=$topHandles
    suspect_pid_mapping=$suspectRows
    wmi_operational_status=$wmiread;wmi_recent_errors=$wmiErrors
    caveats=@('Snapshot, not causation','Service PID mapping is time-dependent','WMI 5858 error count is correlation, not proof')
}
$json=$result|ConvertTo-Json -Depth 7 -Compress
if($OutFile) {
    $path=[IO.Path]::GetFullPath($OutFile)
    $dir=[IO.Path]::GetDirectoryName($path)
    if(-not [IO.Directory]::Exists($dir)){throw 'OUTPUT_PARENT_FOLDER_MUST_EXIST'}
    if([IO.File]::Exists($path)){throw 'OUTPUT_FILE_EXISTS_REFUSE_OVERWRITE'}
    [IO.File]::WriteAllText($path,$json,(New-Object System.Text.UTF8Encoding($false)))
    Write-Host 'RESOURCE_DIAGNOSTIC_FILE_WRITTEN'
} else { Write-Output $json }
