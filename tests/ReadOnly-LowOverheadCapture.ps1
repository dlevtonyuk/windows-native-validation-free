# Low-overhead, READ-ONLY process-pressure sampling research.
# Designed for an already-open Windows session: no windows/tabs/processes are closed.
# No CIM, WMI, tracing, PowerShell background jobs, browser URLs, document names or remote I/O.
[CmdletBinding()]
param(
  [ValidateRange(1,5)][int]$SampleSeconds=1,
  [ValidateRange(2,50)][int]$MaxGroups=20
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$timer=[System.Diagnostics.Stopwatch]::StartNew()
$start=(Get-Date).ToUniversalTime().ToString('o')
# ComputerInfo uses OS physical-memory counters, not a Win32_OperatingSystem WMI call.
Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction Stop
$info=New-Object Microsoft.VisualBasic.Devices.ComputerInfo
$total=[double]$info.TotalPhysicalMemory
$available=[double]$info.AvailablePhysicalMemory
if($total -le 0 -or $available -lt 0 -or $available -gt $total){
  throw 'NATIVE_MEMORY_COUNTER_INVALID'
}
function Probe {
  $rows=@(Get-Process -ErrorAction Stop)
  $cpu=@{}
  foreach($p in $rows){
    try{if($null -ne $p.CPU){$cpu[[int]$p.Id]=[double]$p.CPU}}catch{}
  }
  return [pscustomobject]@{processes=$rows;cpu=$cpu}
}
$before=Probe
$clock=[Diagnostics.Stopwatch]::StartNew()
Start-Sleep -Seconds $SampleSeconds
$after=Probe
$clock.Stop()
$seconds=[Math]::Max(0.001,$clock.Elapsed.TotalSeconds)
$cores=[Math]::Max(1,[Environment]::ProcessorCount)
$groups=@{}
foreach($p in $after.processes){
  $name=[string]$p.ProcessName
  if(!$groups.ContainsKey($name)){
    $groups[$name]=[ordered]@{name=$name;process_count=0;private_mb=0.0;working_mb=0.0;
      handles=0;threads=0;cpu_percent_total_capacity=0.0}
  }
  $g=$groups[$name];$g.process_count++
  try{$g.private_mb += [double]$p.PrivateMemorySize64/1MB}catch{}
  try{$g.working_mb += [double]$p.WorkingSet64/1MB}catch{}
  try{$g.handles += [int]$p.HandleCount}catch{}
  try{$g.threads += [int]$p.Threads.Count}catch{}
  if($after.cpu.ContainsKey([int]$p.Id) -and $before.cpu.ContainsKey([int]$p.Id)){
    $diff=$after.cpu[[int]$p.Id]-$before.cpu[[int]$p.Id]
    if($diff -ge 0 -and $diff -le $seconds*$cores) {
      $g.cpu_percent_total_capacity += 100*$diff/($seconds*$cores)
    }
  }
}
$groupRows=@($groups.Values | Sort-Object -Property private_mb -Descending |
  Select-Object -First $MaxGroups | ForEach-Object {
    [ordered]@{name=$_.name;process_count=[int]$_.process_count;
      private_mb=[Math]::Round($_.private_mb,1);
      working_mb=[Math]::Round($_.working_mb,1);
      handles=[int]$_.handles;threads=[int]$_.threads;
      cpu_percent_total_capacity=[Math]::Round($_.cpu_percent_total_capacity,2)}
  })
$timer.Stop()
[pscustomobject]@{
  schema=1
  captured_utc=$start
  actual_cpu_sample_seconds=[Math]::Round($seconds,3)
  execution_elapsed_seconds=[Math]::Round($timer.Elapsed.TotalSeconds,3)
  ram_total_gb=[Math]::Round($total/1GB,2)
  ram_available_gb=[Math]::Round($available/1GB,2)
  ram_used_pct=[Math]::Round(100*(1-$available/$total),1)
  logical_processors=$cores
  enumerated_processes=@($after.processes).Count
  groups=$groupRows
  no_cim_wmi_queries=$true
  read_only=$true
  provenance='DISPOSABLE_RUNNER_TEST_UNTIL_SEPARATELY_AUTHORIZED'
  caveat='One short CPU sample, cumulative process private commit not physical RAM. Process-level data cannot identify specific browser tabs.'
} | ConvertTo-Json -Depth 5 -Compress
