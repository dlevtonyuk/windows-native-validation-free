# Read-only WMI provider-to-host evidence; no tracing, service/process changes or exports.
# Do not publish results from a user's computer to a public repository.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateRange(1,2147483647)]
    [int]$TargetPid,
    [ValidateRange(1,5)]
    [int]$SampleSeconds=2
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$start=(Get-Date).ToUniversalTime().ToString('o')
$proc=Get-Process -Id $TargetPid -ErrorAction Stop
if($proc.ProcessName -ne 'WmiPrvSE'){throw 'TARGET_NOT_WMI_PROVIDER_HOST'}
$fields=@('ProviderOperation_ExecQueryAsync','ProviderOperation_GetObjectAsync',
          'ProviderOperation_CreateInstanceEnumAsync','ProviderOperation_ExecMethodAsync')
function Capture {
    $all=@(Get-CimInstance -Namespace root\cimv2 -ClassName MSFT_Providers -OperationTimeoutSec 12 -ErrorAction Stop)
    $capture=@{}
    foreach($r in $all){
        if([string]$r.HostProcessIdentifier -ne [string]$TargetPid){continue}
        $key=([string]$r.Provider)+'|'+([string]$r.Namespace)+'|'+([string]$r.HostingGroup)
        if($capture.ContainsKey($key)){continue}
        $counts=@{}
        foreach($field in $fields){
            $raw=$r.CimInstanceProperties[$field].Value
            $counts[$field]=if($null -eq $raw){[uint64]0}else{[uint64]$raw}
        }
        $capture[$key]=[pscustomobject]@{
            provider=[string]$r.Provider
            namespace=[string]$r.Namespace
            hosting_group=[string]$r.HostingGroup
            counts=$counts
        }
    }
    return $capture
}
$first=Capture
Start-Sleep -Seconds $SampleSeconds
$second=Capture
$records=@()
foreach($key in ($second.Keys|Sort-Object)){
    $item=$second[$key];$diff=@{};$isComparable=$first.ContainsKey($key)
    foreach($field in $fields){
        $after=[uint64]$item.counts[$field]
        $before=if($isComparable){[uint64]$first[$key].counts[$field]}else{[uint64]0}
        $diff[$field]=if($isComparable -and $after -ge $before){[uint64]($after-$before)}else{$null}
    }
    $records+= [pscustomobject]@{
        provider=$item.provider
        namespace=$item.namespace
        hosting_group=$item.hosting_group
        comparable=$isComparable
        operation_deltas=$diff
    }
}
$eventCount=0;$eventsMatching=0;$eventState='UNTESTED'
try {
    $evt=@(Get-WinEvent -FilterHashtable @{
       LogName='Microsoft-Windows-WMI-Activity/Operational'
       Id=5857
       StartTime=(Get-Date).AddMinutes(-30)
    } -MaxEvents 100 -ErrorAction Stop)
    $eventCount=$evt.Count
    foreach($e in $evt){
        [xml]$doc=$e.ToXml()
        $n=$doc.SelectSingleNode('//*[local-name()="Operation_StartedOperational"]/*[local-name()="ProcessID"]')
        if($n -and [string]$n.InnerText -eq [string]$TargetPid){$eventsMatching++}
    }
    $eventState='OK'
} catch {
    $eventState='NO_EVENTS_OR_PERMISSION'
}
[pscustomobject]@{
    schema=1
    target_pid=$TargetPid
    captured_utc=$start
    sample_seconds=$SampleSeconds
    process_alive_start=$true
    provider_count=$records.Count
    providers=$records
    recent_event_5857_total=$eventCount
    recent_event_5857_matching_pid=$eventsMatching
    recent_event_status=$eventState
    read_only=$true
    note='Operation deltas are correlation evidence only; provider identity does not prove CPU causation. A process PID may be reused after exit.'
} | ConvertTo-Json -Depth 7 -Compress
