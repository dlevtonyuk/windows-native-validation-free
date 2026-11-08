# Generic disposable-runner feasibility probe only; no tracing, system writes or user data.
# Intended to validate whether MSFT_Providers exposes host PID attribution through read-only CIM.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$providerState='UNTESTED'; $providerCount=0; $matchCount=0
$hasPidField=$false; $eventState='UNTESTED'; $eventCount=0; $eventPidCount=0
try {
    $rows=@(Get-CimInstance -Namespace 'root\cimv2' -ClassName MSFT_Providers -OperationTimeoutSec 12 -ErrorAction Stop)
    $providerCount=$rows.Count
    if($providerCount -eq 0){$providerState='NO_PROVIDER_ROWS'}
    else {
        $hasPidField=(@($rows[0].CimInstanceProperties.Name) -contains 'HostProcessIdentifier')
        if(-not $hasPidField){$providerState='NO_PID_FIELD'}
        else {
            $hosts=@(Get-CimInstance -ClassName Win32_Process -Filter "Name='WmiPrvSE.exe'" -OperationTimeoutSec 12 -ErrorAction Stop)
            $ids=@{}; foreach($hostrow in $hosts){$ids[[string]$hostrow.ProcessId]=$true}
            foreach($row in $rows) {
                if($null -ne $row.HostProcessIdentifier -and $ids.ContainsKey([string]$row.HostProcessIdentifier)){
                    $matchCount++
                }
            }
            $providerState='QUERY_SUPPORTED'
        }
    }
} catch { $providerState='PROVIDER_QUERY_FAILED' }
try {
    $events=@(Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-WMI-Activity/Operational'
        Id=5857
        StartTime=(Get-Date).AddHours(-1)
    } -MaxEvents 40 -ErrorAction Stop)
    $eventCount=$events.Count
    foreach($ev in $events){
        [xml]$xml=$ev.ToXml()
        $node=$xml.SelectSingleNode('//*[local-name()="Operation_StartedOperational"]/*[local-name()="ProcessID"]')
        if($node -and $node.InnerText -match '^\d+$'){$eventPidCount++}
    }
    $eventState='EVENT_XML_QUERY_SUPPORTED'
} catch [System.Exception] {
    $eventState='NO_EVENTS_OR_PERMISSION'
}
[pscustomobject]@{
    schema=1
    provider_query_state=$providerState
    provider_rows=$providerCount
    provider_host_pid_field=$hasPidField
    provider_current_host_matches=$matchCount
    recent_event_state=$eventState
    recent_event_rows=$eventCount
    recent_event_pid_fields=$eventPidCount
    provenance='DISPOSABLE_GITHUB_WINDOWS_HOST_NOT_USER_PC'
} | ConvertTo-Json -Compress
