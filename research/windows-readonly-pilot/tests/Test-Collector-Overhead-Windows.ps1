# Disposable GitHub Windows runner ONLY. No user devices, networking, services,
# Scheduled Tasks, WMI, persistence or Cloudflare credentials.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_OS -cne 'Windows') {throw 'DISPOSABLE_WINDOWS_RUNNER_REQUIRED'}
$source=Join-Path $PSScriptRoot '..\windows\Collect-ReadOnlyAggregate.ps1'
if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {throw 'COLLECTOR_NOT_FOUND'}
$proc=[System.Diagnostics.Process]::GetCurrentProcess()
$totals=[System.Collections.Generic.List[double]]::new()
$cpuTotals=[System.Collections.Generic.List[double]]::new()
try {
 for($i=0;$i -lt 3;$i++){
  $cpuBefore=$proc.TotalProcessorTime.TotalMilliseconds
  $watch=[System.Diagnostics.Stopwatch]::StartNew()
  $raw=& $source -CpuSampleMilliseconds 300
  $watch.Stop()
  $cpuAfter=$proc.TotalProcessorTime.TotalMilliseconds
  $sample=$raw | ConvertFrom-Json
  if($sample.schema -ne 1 -or $sample.evidence_kind -cne 'aggregate_windows_readonly') {throw 'SCHEMA_INVALID'}
  if($sample.ram_used_pct -lt 0 -or $sample.ram_used_pct -gt 100 -or $sample.process_count -le 0){throw 'VALUES_INVALID'}
  if($null -ne $sample.cpu_used_pct -and ($sample.cpu_used_pct -lt 0 -or $sample.cpu_used_pct -gt 100)){throw 'CPU_RANGE_INVALID'}
  $totals.Add([double]$watch.Elapsed.TotalMilliseconds)
  $cpuTotals.Add([Math]::Max(0.0,[double]($cpuAfter-$cpuBefore)))
 }
 $avgWall=[Math]::Round(($totals|Measure-Object -Average).Average,2)
 $avgCpu=[Math]::Round(($cpuTotals|Measure-Object -Average).Average,2)
 $maxWall=[Math]::Round(($totals|Measure-Object -Maximum).Maximum,2)
 $peakMB=[Math]::Round([double]$proc.PeakWorkingSet64/1MB,2)
 Write-Output ("DISPOSABLE_WINDOWS_CPU_SAMPLER_OVERHEAD_PASS count=3 avg_wall_ms={0} max_wall_ms={1} avg_powershell_cpu_ms={2} process_peak_workingset_mb={3}" -f $avgWall,$maxWall,$avgCpu,$peakMB)
} finally {$proc.Dispose()}