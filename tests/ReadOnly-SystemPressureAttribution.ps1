# Research-only, read-only process and WMI attribution.
# No process changes, service changes, tracing, credential reads, tab titles, URLs or uploads.
# Actual user-PC use requires a separately authorized fixed read-only connector operation.
[CmdletBinding()]
param(
  [ValidateRange(1,5)][int]$SampleSeconds=2,
  [ValidateRange(1,25)][int]$MaxProcesses=12,
  [int[]]$TargetPids=@()
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$watchNames=@('WmiPrvSE','Bright VPN','dwm','explorer','MsMpEng',
              'svchost','powershell','tunnel-client')
$start=(Get-Date).ToUniversalTime().ToString('o')
$cores=[Math]::Max(1,[Environment]::ProcessorCount)
$all=@(Get-Process -ErrorAction Stop)
$targetSet=@{}
foreach($pidItem in $TargetPids){
  if($pidItem -gt 0){$targetSet[[int]$pidItem]=$true}
}
foreach($p in $all){
  if($watchNames -contains $p.ProcessName) {$targetSet[[int]$p.Id]=$true}
}
# Keep a bounded set of individually matched processes; no all-system 
# per-thread enumeration and no reading browser titles or URLs.
$targets=@($all | Where-Object {$targetSet.ContainsKey([int]$_.Id)} |
  Sort-Object PrivateMemorySize64 -Descending | Select-Object -First $MaxProcesses)
function Sample([array]$items) {
  $map=@{}
  foreach($p in $items) {
    try {
      $now=Get-Process -Id $p.Id -ErrorAction Stop
      $time=if($null -eq $now.CPU){$null}else{[double]$now.CPU}
      $map[[int]$p.Id]=[pscustomobject]@{
        name=[string]$now.ProcessName; pid=[int]$now.Id;
        cpu_seconds=$time
        private_mb=[Math]::Round([double]$now.PrivateMemorySize64/1MB,1)
        working_mb=[Math]::Round([double]$now.WorkingSet64/1MB,1)
        handles=[int]$now.HandleCount
        threads=[int]$now.Threads.Count
      }
    } catch { }
  }
  return $map
}
$a=Sample $targets
$timer=[Diagnostics.Stopwatch]::StartNew()
Start-Sleep -Seconds $SampleSeconds
$b=Sample $targets
$timer.Stop()
$seconds=[Math]::Max(0.01,$timer.Elapsed.TotalSeconds)
$records=@()
foreach($id in ($b.Keys | Sort-Object)) {
  $second=$b[$id]
  $first=$a[$id]
  $cpuRate=$null
  if($null -ne $first -and $null -ne $first.cpu_seconds -and
     $null -ne $second.cpu_seconds -and $second.cpu_seconds -ge $first.cpu_seconds) {
    $cpuRate=[Math]::Round(100*([double]$second.cpu_seconds-[double]$first.cpu_seconds)/($seconds*$cores),2)
  }
  $records+=[ordered]@{
    name=$second.name; pid=[int]$id;
    cpu_percent_total_capacity=$cpuRate
    private_mb=$second.private_mb; working_mb=$second.working_mb
    handles=$second.handles; threads=$second.threads
    handle_delta=if($first){[int]($second.handles-$first.handles)}else{$null}
    thread_delta=if($first){[int]($second.threads-$first.threads)}else{$null}
  }
}
$mapStatus='NOT_REQUESTED'
$providers=@()
$hosts=@($targets|Where-Object {$_.ProcessName -eq 'WmiPrvSE'})
if($hosts.Count -gt 0){
  try {
    $hostIds=@{};foreach($h in $hosts){$hostIds[[string]$h.Id]=$true}
    $allProviders=@(Get-CimInstance -Namespace root\cimv2 -ClassName MSFT_Providers -OperationTimeoutSec 8 -ErrorAction Stop)
    foreach($p in $allProviders){
      $hostPid=[string]$p.HostProcessIdentifier
      if($hostIds.ContainsKey($hostPid)) {
        $providers += [ordered]@{host_pid=[int]$p.HostProcessIdentifier
          provider=[string]$p.Provider; namespace=[string]$p.Namespace}
      }
    }
    $mapStatus='AVAILABLE'
  } catch {$mapStatus='UNAVAILABLE_OR_TIMEOUT'}
}
[pscustomobject]@{
  schema=1
  captured_utc=$start
  elapsed_seconds=[Math]::Round($seconds,2)
  logical_processors=$cores
  process_data=$records
  provider_mapping_status=$mapStatus
  wmi_providers=$providers
  read_only=$true
  provenance='RESEARCH_ONLY'
  caveat='Process CPU is a short interval; a loaded WMI provider is not proven responsible for CPU; browser tab attribution requires browser-internal data.'
} | ConvertTo-Json -Depth 6 -Compress
