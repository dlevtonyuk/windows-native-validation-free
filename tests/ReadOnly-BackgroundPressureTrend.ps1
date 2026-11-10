# Read-only, no-WMI PID-level background pressure comparison.
# Does NOT inspect tabs, URLs, command lines, open files, credentials or network traffic.
# Does NOT stop processes, alter Windows settings or install anything.
[CmdletBinding()]
param(
  [string[]]$ProcessNames=@('Bright VPN','WmiPrvSE','tunnel-client','explorer','dwm','MsMpEng'),
  [ValidateRange(1,5)][int]$SampleSeconds=2,
  [ValidateRange(1,50)][int]$MaxProcesses=24
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$now=(Get-Date).ToUniversalTime().ToString('o')
$names=@{}
foreach($n in $ProcessNames){if(-not [string]::IsNullOrWhiteSpace($n)){$names[$n.ToLowerInvariant()]=$true}}
if($names.Count -eq 0){throw 'NO_PROCESS_NAMES'}
function Capture {
  $result=@{}
  $matches=@(Get-Process -ErrorAction Stop | Where-Object {
    $names.ContainsKey($_.ProcessName.ToLowerInvariant())
  } | Sort-Object PrivateMemorySize64 -Descending | Select-Object -First $MaxProcesses)
  foreach($p in $matches){
    try {
      $process=Get-Process -Id $p.Id -ErrorAction Stop
      $started=$null
      try{$started=$process.StartTime.ToUniversalTime().Ticks}catch{}
      $result[[int]$process.Id]=[pscustomobject]@{
        name=[string]$process.ProcessName
        pid=[int]$process.Id
        started_utc_ticks=$started
        cpu_seconds=if($null -ne $process.CPU){[double]$process.CPU}else{$null}
        private_mb=[Math]::Round([double]$process.PrivateMemorySize64/1MB,1)
        working_mb=[Math]::Round([double]$process.WorkingSet64/1MB,1)
        handles=[int]$process.HandleCount
        threads=[int]$process.Threads.Count
      }
    }catch{}
  }
  return $result
}
$a=Capture
$timer=[Diagnostics.Stopwatch]::StartNew()
Start-Sleep -Seconds $SampleSeconds
$b=Capture
$timer.Stop()
$seconds=[Math]::Max(0.001,$timer.Elapsed.TotalSeconds)
$cores=[Math]::Max(1,[Environment]::ProcessorCount)
$rows=@()
foreach($id in ($b.Keys|Sort-Object)){
  $curr=$b[$id]
  $prev=$a[$id]
  $same=($null -ne $prev)
  if($same -and $null -ne $prev.started_utc_ticks -and $null -ne $curr.started_utc_ticks){
    $same=($prev.started_utc_ticks -eq $curr.started_utc_ticks)
  }
  $rate=$null;$handleDelta=$null;$threadDelta=$null
  if($same){
    $handleDelta=[int]($curr.handles-$prev.handles)
    $threadDelta=[int]($curr.threads-$prev.threads)
    if($null -ne $prev.cpu_seconds -and $null -ne $curr.cpu_seconds){
      $delta=$curr.cpu_seconds-$prev.cpu_seconds
      if($delta -ge 0 -and $delta -le $seconds*$cores){
        $rate=[Math]::Round(100*$delta/($seconds*$cores),2)
      }
    }
  }
  $rows+= [ordered]@{
    name=$curr.name;pid=[int]$id
    stable_pid_and_start_time=$same
    cpu_percent_total_capacity=$rate
    private_mb=$curr.private_mb
    working_mb=$curr.working_mb
    handles=$curr.handles
    threads=$curr.threads
    handle_delta=$handleDelta
    thread_delta=$threadDelta
    flagged_high_threads=($curr.threads -ge 1000)
    flagged_high_handles=($curr.handles -ge 20000)
  }
}
[pscustomobject]@{
  schema=1
  captured_utc=$now
  sample_seconds=[Math]::Round($seconds,2)
  logical_processors=$cores
  processes=$rows
  matched_pid_count=$rows.Count
  read_only=$true
  no_wmi=$true
  no_browser_session_inspection=$true
  caveat='High counts are triage flags, not proof of leak. Two samples cannot identify a trend. Unavailable data is null. Does not attribute Firefox/Chrome tab usage.'
} | ConvertTo-Json -Compress -Depth 6
