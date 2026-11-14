# Executes ONLY on disposable GitHub-hosted Windows; neither installs nor transmits.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_OS -cne 'Windows') {throw 'DISPOSABLE_GITHUB_WINDOWS_RUNNER_REQUIRED'}
$source=Join-Path $PSScriptRoot '..\windows\Inspect-LagSignals-LOCALONLY-NOT-RUN.ps1'
if(-not(Test-Path -LiteralPath $source -PathType Leaf)){throw 'LAG_PROBE_SOURCE_MISSING'}
$read=[IO.File]::ReadAllText([IO.Path]::GetFullPath($source))
foreach($banned in @('Invoke-WebRequest','Invoke-RestMethod','Start-Process','Register-ScheduledTask','New-ScheduledTask','Set-ItemProperty','Get-CimInstance','Get-WmiObject')){
    if($read -like ('*'+$banned+'*')){throw ('UNEXPECTED_BEHAVIOR_'+$banned)}
}
$watch=[System.Diagnostics.Stopwatch]::StartNew()
$first=(& $source -SkipPerformanceCounters -SkipEventLog -SkipProviderCpu -LookbackMinutes 2 | ConvertFrom-Json)
$watch.Stop()
if($first.schema -ne 1 -or $first.evidence_kind -cne 'local_only_lag_triage_aggregates'){throw 'SCHEMA_OR_EVIDENCE_KIND_FAILED'}
if($first.performance_counter_status -ne 'SKIPPED' -or $first.wmi_operational_status -ne 'SKIPPED' -or $first.wmi_provider_cpu_status -ne 'SKIPPED'){throw 'SKIP_GUARD_FAILED'}
if($null -ne $first.wmi_provider_cpu_pct_total_capacity -or $null -ne $first.wmi_provider_cpu_sample_elapsed_ms -or $first.wmi_provider_cpu_matched_process_count -ne 0){throw 'WMI_CPU_SKIP_DATA_LEAKED'}
if($first.wmi_provider_status -notin @('OK','UNAVAILABLE')){throw 'WMI_PROVIDER_STATUS_UNKNOWN'}
if($first.wmi_provider_status -eq 'OK' -and $first.wmi_provider_count -lt 0){throw 'WMI_PROVIDER_COUNT_INVALID'}
if($null -ne $first.physical_disk_average_transfer_latency_ms -or $null -ne $first.wmi_5858_error_count){throw 'SKIPPED_MEASUREMENT_LEAKED'}
if($first.PSObject.Properties.Name -contains 'pid' -or $first.PSObject.Properties.Name -contains 'user'){throw 'PRIVACY_OUTPUT_INVALID'}
if($watch.Elapsed.TotalSeconds -gt 25){throw 'BASELINE_COLLECTOR_EXCESSIVE_DURATION'}
$baselineMs=[Math]::Round($watch.Elapsed.TotalMilliseconds,0)
$watch.Restart()
$full=(& $source -LookbackMinutes 2 | ConvertFrom-Json)
$watch.Stop()
if($full.evidence_kind -cne 'local_only_lag_triage_aggregates'){throw 'FULL_PROBE_EVIDENCE_KIND_FAILED'}
if($full.performance_counter_status -notin @('OK','PARTIAL','UNAVAILABLE')){throw 'COUNTER_STATUS_INVALID'}
if($full.wmi_operational_status -notin @('OK','UNAVAILABLE','DISABLED')){throw 'WMI_LOG_STATUS_INVALID'}
if($full.wmi_provider_cpu_status -notin @('OK','PARTIAL','UNAVAILABLE')){throw 'WMI_CPU_STATUS_INVALID'}
if($full.wmi_provider_cpu_status -eq 'UNAVAILABLE' -and $null -ne $full.wmi_provider_cpu_pct_total_capacity){throw 'UNAVAILABLE_WMI_CPU_MUST_BE_NULL'}
if($full.wmi_provider_cpu_status -in @('OK','PARTIAL')) {
    if($null -eq $full.wmi_provider_cpu_pct_total_capacity -or $full.wmi_provider_cpu_pct_total_capacity -lt 0 -or $full.wmi_provider_cpu_pct_total_capacity -gt 100) {throw 'WMI_CPU_RANGE_INVALID'}
}
if($null -eq $full.wmi_provider_cpu_sample_elapsed_ms -or $full.wmi_provider_cpu_sample_elapsed_ms -lt 250 -or $full.wmi_provider_cpu_sample_elapsed_ms -gt 15000){throw 'WMI_CPU_SAMPLE_TIME_INVALID'}
if($full.PSObject.Properties.Name -contains 'pid' -or $full.PSObject.Properties.Name -contains 'process_name'){throw 'WMI_CPU_PRIVACY_LEAK'}
if($full.wmi_operational_status -eq 'OK' -and ($null -eq $full.wmi_5858_error_count -or $full.wmi_5858_error_count -lt 0 -or $full.wmi_5858_error_count -gt 100)){throw 'WMI_ERROR_COUNT_INVALID'}
if($full.wmi_operational_status -ne 'OK' -and $null -ne $full.wmi_5858_error_count){throw 'WMI_LOG_NOT_AVAILABLE_BUT_COUNT_PRESENT'}
if($watch.Elapsed.TotalSeconds -gt 25){throw 'FULL_PROBE_EXCESSIVE_DURATION'}
Write-Output ("WINDOWS_LOCALONLY_LAG_PROBE_PASS baseline_ms=$baselineMs full_ms=$([Math]::Round($watch.Elapsed.TotalMilliseconds,0)) disk_status=$($full.performance_counter_status) wmi_log_status=$($full.wmi_operational_status) wmi_cpu_status=$($full.wmi_provider_cpu_status) wmi_cpu_pct_capacity=$($full.wmi_provider_cpu_pct_total_capacity)")