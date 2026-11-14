# Source-only, Windows PowerShell 5.1, no modification of Windows configuration.
# SampleOnly produces a local result; network upload is not implemented in this component.
# No WMI/CIM calls, process names, PIDs, browsing data, file paths or process command lines.
[CmdletBinding()]
param([ValidateRange(300,2000)][int]$CpuSampleMilliseconds=1000)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) {
  # Windows PowerShell 5.1 does not define IsWindows; cross-platform PowerShell Core does.
  throw 'WINDOWS_ONLY_COLLECTOR'
}
$native=@'
using System;
using System.Runtime.InteropServices;
public static class CWFRPrivateAggregateNative {
 [StructLayout(LayoutKind.Sequential)] public struct FT { public uint Low; public uint High; }
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Auto)] public sealed class MEM {
  public uint Length; public uint Load;
  public ulong TotalPhys; public ulong AvailPhys;
  public ulong TotalPageFile; public ulong AvailPageFile;
  public ulong TotalVirtual; public ulong AvailVirtual; public ulong AvailExtendedVirtual;
  public MEM(){ Length=(uint)Marshal.SizeOf(typeof(MEM)); }
 }
 [DllImport("kernel32.dll",SetLastError=true)] private static extern bool GetSystemTimes(out FT idle,out FT kernel,out FT user);
 [DllImport("kernel32.dll",SetLastError=true)] private static extern bool GlobalMemoryStatusEx([In,Out] MEM memory);
 public sealed class CPU { public ulong Idle; public ulong Kernel; public ulong User; }
 private static ulong UInt64(FT t){ return (((ulong)t.High)<<32)|t.Low; }
 public static CPU CaptureCPU(){FT i,k,u;if(!GetSystemTimes(out i,out k,out u))throw new InvalidOperationException("CPU_QUERY_FAILED");return new CPU{Idle=UInt64(i),Kernel=UInt64(k),User=UInt64(u)};}
 public static MEM CaptureMemory(){MEM m=new MEM();if(!GlobalMemoryStatusEx(m))throw new InvalidOperationException("MEMORY_QUERY_FAILED");return m;}
}
'@
if(-not ('CWFRPrivateAggregateNative' -as [type])) {Add-Type -TypeDefinition $native -ErrorAction Stop}
$before=[CWFRPrivateAggregateNative]::CaptureCPU()
Start-Sleep -Milliseconds $CpuSampleMilliseconds
$after=[CWFRPrivateAggregateNative]::CaptureCPU()
$mem=[CWFRPrivateAggregateNative]::CaptureMemory()
if($mem.TotalPhys -le 0){throw 'INVALID_PHYSICAL_MEMORY'}
$kernel=[double]($after.Kernel-$before.Kernel)
$user=[double]($after.User-$before.User)
$idle=[double]($after.Idle-$before.Idle)
$total=$kernel+$user
$cpu=$null
if($total -gt 0 -and $idle -ge 0 -and $idle -le $total) {
    $cpu=[Math]::Round((100.0*($total-$idle)/$total),2)
}
$ramTotal=[int64][Math]::Round([double]$mem.TotalPhys/1MB,0)
$ramAvail=[int64][Math]::Round([double]$mem.AvailPhys/1MB,0)
$ramUsed=[Math]::Round(100.0*(1.0-[double]$mem.AvailPhys/[double]$mem.TotalPhys),2)
$commit=$null
if($mem.TotalPageFile -gt 0) {$commit=[Math]::Round(100.0*(1.0-[double]$mem.AvailPageFile/[double]$mem.TotalPageFile),2)}
$procs=[System.Diagnostics.Process]::GetProcesses()
$processCount=$procs.Length
foreach($p in $procs){$p.Dispose()}
$payload=[ordered]@{
 schema=1
 evidence_kind='aggregate_windows_readonly'
 sample_id=([Guid]::NewGuid().ToString('D'))
 observed_ms=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
 cpu_used_pct=$cpu
 ram_used_pct=$ramUsed
 ram_total_mb=$ramTotal
 ram_available_mb=$ramAvail
 commit_used_pct=$commit
 process_count=$processCount
}
# This command reports aggregate numeric values only; a separate, owner-approved sender is required.
$payload|ConvertTo-Json -Compress -Depth 3