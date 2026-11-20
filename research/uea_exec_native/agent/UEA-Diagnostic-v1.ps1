# Owner-approved, non-effect diagnostic package for UEA v0.5 execution proof.
# Makes no external requests; has no parameters and performs no business writes.
# Output is intentionally limited to generic execution evidence.
#requires -Version 5.1
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
if($env:OS -ne 'Windows_NT'){throw 'WINDOWS_ONLY'}
$proof=[ordered]@{
 schema=1
 kind='UEA_SIGNED_REMOTE_EXECUTION_PROOF'
 executed_utc=([DateTime]::UtcNow.ToString('o'))
 powershell_major=[int]$PSVersionTable.PSVersion.Major
 process_id=[int]$PID
 non_privileged= -not ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
 business_writes=0
}
$proof|ConvertTo-Json -Depth 4 -Compress|Write-Output