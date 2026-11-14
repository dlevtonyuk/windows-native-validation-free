# Standalone, owner-controlled, LOCAL-ONLY lag evidence. Do not install, schedule or transmit.
# Must never run under the unapproved v4 cloud sender. No remote access, writes, or registry edits.
# Privacy: output exclusively numeric aggregates and availability flags, no names, PID, paths,
# WMI event messages, users, command lines, device identifiers, file inventory or process list.
[CmdletBinding()]
param(
    [ValidateRange(1,30)][int]$LookbackMinutes=15,
    [switch]$SkipPerformanceCounters,
    [switch]$SkipEventLog
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) { throw 'WINDOWS_ONLY_LOCAL_DIAGNOSTIC' }

$providerCount=$null
$providerWorkingMb=$null
$providerPrivateMb=$null
$providerStatus='UNAVAILABLE'
$instances=@()
try {
    $instances=@([System.Diagnostics.Process]::GetProcessesByName('WmiPrvSE'))
    $sumWorking=[double]0; $sumPrivate=[double]0
    foreach($instance in $instances) {
        $sumWorking += [double]$instance.WorkingSet64
        $sumPrivate += [double]$instance.PrivateMemorySize64
    }
    $providerCount=$instances.Count
    $providerWorkingMb=[Math]::Round($sumWorking/1MB,2)
    $providerPrivateMb=[Math]::Round($sumPrivate/1MB,2)
    $providerStatus='OK'
} catch {
    $providerStatus='UNAVAILABLE'
} finally {
    foreach($instance in $instances) {if($null -ne $instance){$instance.Dispose()}}
}

$diskLatencyMs=$null; $diskTransfersPerSec=$null; $pageReadsPerSec=$null
$counterStatus=if($SkipPerformanceCounters){'SKIPPED'}else{'UNAVAILABLE'}
if(-not $SkipPerformanceCounters) {
    try {
        # Windows performance counters; sampling is bounded to two instances and one second.
        # Names may be localized or counters unavailable: return UNAVAILABLE, never zero.
        $counterPaths=@(
            '\PhysicalDisk(_Total)\Avg. Disk sec/Transfer',
            '\PhysicalDisk(_Total)\Disk Transfers/sec',
            '\Memory\Page Reads/sec'
        )
        $samples=@(Get-Counter -Counter $counterPaths -SampleInterval 1 -MaxSamples 2 -ErrorAction Stop)
        if($samples.Count -ge 2) {
            $last=$samples[$samples.Count-1]
            foreach($cs in @($last.CounterSamples)) {
                $value=[double]$cs.CookedValue
                if([double]::IsNaN($value) -or [double]::IsInfinity($value) -or $value -lt 0) {continue}
                $path=([string]$cs.Path).ToLowerInvariant()
                if($path.EndsWith('\physicaldisk(_total)\avg. disk sec/transfer')){
                    $diskLatencyMs=[Math]::Round($value*1000,3)
                } elseif($path.EndsWith('\physicaldisk(_total)\disk transfers/sec')){
                    $diskTransfersPerSec=[Math]::Round($value,2)
                } elseif($path.EndsWith('\memory\page reads/sec')){
                    $pageReadsPerSec=[Math]::Round($value,2)
                }
            }
        }
        if($null -ne $diskLatencyMs -and $null -ne $diskTransfersPerSec -and $null -ne $pageReadsPerSec) {$counterStatus='OK'}
        elseif($null -ne $diskLatencyMs -or $null -ne $diskTransfersPerSec -or $null -ne $pageReadsPerSec){$counterStatus='PARTIAL'}
    } catch {$counterStatus='UNAVAILABLE'}
}

$wmiErrors=$null; $wmiErrorStatus=if($SkipEventLog){'SKIPPED'}else{'UNAVAILABLE'}
$eventsCapped=$false
if(-not $SkipEventLog) {
    try {
        $log=Get-WinEvent -ListLog 'Microsoft-Windows-WMI-Activity/Operational' -ErrorAction Stop
        if(-not $log.IsEnabled) {$wmiErrorStatus='DISABLED'} else {
            try {
                $evts=@(Get-WinEvent -FilterHashtable @{
                    LogName='Microsoft-Windows-WMI-Activity/Operational'
                    Id=5858
                    StartTime=(Get-Date).AddMinutes(-$LookbackMinutes)
                } -MaxEvents 100 -ErrorAction Stop)
                $wmiErrors=$evts.Count
                $eventsCapped=($wmiErrors -ge 100)
                $wmiErrorStatus='OK'
            } catch {
                # An enabled log containing no matching events is meaningfully zero.
                if($_.FullyQualifiedErrorId -like '*NoMatchingEventsFound*') {
                    $wmiErrors=0; $wmiErrorStatus='OK'
                } else {$wmiErrorStatus='UNAVAILABLE'}
            }
        }
    } catch {$wmiErrorStatus='UNAVAILABLE'}
}

# The report is LOCAL ONLY. No sender accepts this schema. A single snapshot cannot prove causation.
$report=[ordered]@{
    schema=1
    evidence_kind='local_only_lag_triage_aggregates'
    observed_utc=[DateTimeOffset]::UtcNow.ToString('o')
    wmi_provider_status=$providerStatus
    wmi_provider_count=$providerCount
    wmi_provider_working_set_total_mb=$providerWorkingMb
    wmi_provider_private_commit_total_mb=$providerPrivateMb
    performance_counter_status=$counterStatus
    physical_disk_average_transfer_latency_ms=$diskLatencyMs
    physical_disk_transfers_per_second=$diskTransfersPerSec
    memory_page_reads_per_second=$pageReadsPerSec
    wmi_operational_status=$wmiErrorStatus
    wmi_5858_errors_last_minutes=$LookbackMinutes
    wmi_5858_error_count=$wmiErrors
    wmi_event_count_capped_at_100=$eventsCapped
    interpretation='Single aggregate snapshot; correlation only; unavailable values are null; do not infer a healthy system from missing data.'
}
$report|ConvertTo-Json -Compress -Depth 3