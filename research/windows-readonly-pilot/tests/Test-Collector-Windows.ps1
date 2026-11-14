# Disposable GH-hosted Windows runner only; no user device access, no network, no file writes.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$script=Join-Path $PSScriptRoot '..\windows\Collect-ReadOnlyAggregate.ps1'
$raw=& $script -CpuSampleMilliseconds 500
$o=$raw|ConvertFrom-Json
$expected=@('schema','evidence_kind','sample_id','observed_ms','cpu_used_pct','ram_used_pct','ram_total_mb','ram_available_mb','commit_used_pct','process_count')|Sort-Object
$actual=@($o.PSObject.Properties.Name)|Sort-Object
if(($expected -join ',') -cne ($actual -join ',')){throw 'UNEXPECTED_FIELD_SET'}
if($o.schema -ne 1 -or $o.evidence_kind -cne 'aggregate_windows_readonly'){throw 'INVALID_SCHEMA'}
if($o.sample_id -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'){throw 'NOT_A_RANDOM_V4_UUID'}
if($o.ram_total_mb -lt 128 -or $o.ram_available_mb -lt 0 -or $o.ram_available_mb -gt $o.ram_total_mb){throw 'MEMORY_INVALID'}
if($o.ram_used_pct -lt 0 -or $o.ram_used_pct -gt 100){throw 'MEMORY_PERCENT_INVALID'}
if($null -ne $o.cpu_used_pct -and ($o.cpu_used_pct -lt 0 -or $o.cpu_used_pct -gt 100)){throw 'CPU_PERCENT_INVALID'}
if($null -ne $o.commit_used_pct -and ($o.commit_used_pct -lt 0 -or $o.commit_used_pct -gt 100)){throw 'COMMIT_PERCENT_INVALID'}
if($o.process_count -lt 1 -or $o.process_count -gt 100000){throw 'PROCESS_COUNT_INVALID'}
if([Math]::Abs([double]$o.ram_used_pct-(100*(1-[double]$o.ram_available_mb/[double]$o.ram_total_mb))) -gt 1.5){throw 'MEMORY_INCONSISTENT'}
Write-Output 'WINDOWS_NATIVE_READONLY_COLLECTOR_PASS'