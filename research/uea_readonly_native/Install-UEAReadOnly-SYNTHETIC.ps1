#requires -Version 5.1
# Separate additive read-only device agent v0.4. Preserves installed heartbeat agent.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$src=Split-Path -Parent $MyInvocation.MyCommand.Path
$taskName='ChatGPT UEA Device Agent - ReadOnly'
$hbTask='ChatGPT UEA Device Agent - Heartbeat'
$root=Join-Path $env:LOCALAPPDATA 'ChatGPT\UEA-ReadOnlyAgent'
$hbRoot=Join-Path $env:LOCALAPPDATA 'ChatGPT\UEA-DeviceAgent'
$allowRoot='C:\UEA-SYNTHETIC\TESTROOT'
$worker='https://example.invalid/health'
$ownerKeyName=$null;$ownerRsa=$null;$created=$false;$taskCreated=$false
function Url64([byte[]]$b){return [Convert]::ToBase64String($b).TrimEnd('=').Replace('+','-').Replace('/','_')}
try {
 if($env:OS -ne 'Windows_NT' -or $PSVersionTable.PSVersion.Major -lt 5){throw 'WINDOWS_POWERSHELL_5_REQUIRED'}
 if([Security.Principal.WindowsIdentity]::GetCurrent().IsSystem){throw 'SYSTEM_INSTALL_DENIED'}
 if(Test-Path -LiteralPath $root){throw 'READONLY_AGENT_ALREADY_EXISTS_PRESERVE_ORIGINAL'}
 if(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue){throw 'READONLY_TASK_ALREADY_EXISTS_PRESERVE_ORIGINAL'}
 if(-not(Get-ScheduledTask -TaskName $hbTask -ErrorAction SilentlyContinue)){throw 'BASE_HEARTBEAT_TASK_MISSING'}
 $hbCfgPath=Join-Path $hbRoot 'device-public.json'
 if(-not(Test-Path -LiteralPath $hbCfgPath -PathType Leaf)){throw 'HEARTBEAT_IDENTITY_MISSING'}
 $device=Get-Content -LiteralPath $hbCfgPath -Raw|ConvertFrom-Json
 if($device.version -ne 1 -or $device.device_id -notmatch '^dev_[a-f0-9]{32}$' -or $device.key_container -notmatch '^UEA-DeviceIdentity-[a-f0-9]{32}$'){throw 'HEARTBEAT_IDENTITY_INVALID'}
 if(-not(Test-Path -LiteralPath $allowRoot -PathType Container)){throw 'APPROVED_SOURCE_ROOT_NOT_FOUND'}
 if((Get-Item -LiteralPath $allowRoot -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'SOURCE_ROOT_IS_REPARSE_POINT'}
 $program=Join-Path $src 'Run-UEAReadOnly.ps1';$cert=Join-Path $src 'recipient.cer'
 if(-not(Test-Path -LiteralPath $program -PathType Leaf) -or -not(Test-Path -LiteralPath $cert -PathType Leaf)){throw 'PACKAGE_FILES_MISSING'}
 if((Get-FileHash -LiteralPath $program -Algorithm SHA256).Hash -cne '__AGENT_SOURCE_SHA256__'){throw 'AGENT_SOURCE_HASH_MISMATCH'}
 if((Get-FileHash -LiteralPath $cert -Algorithm SHA256).Hash -cne '__RECIPIENT_CERT_SHA256__'){throw 'RECEIVER_CERT_HASH_MISMATCH'}
 # Reject a changed/malicious cloud route or an unexpected mode before installation.
 [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
 $req=[Net.HttpWebRequest][Net.WebRequest]::Create($worker);$req.AllowAutoRedirect=$false;$req.Timeout=12000
 $r=[Net.HttpWebResponse]$req.GetResponse()
 try {if([int]$r.StatusCode -ne 200){throw 'CLOUD_HEALTH_UNEXPECTED'};$sr=New-Object IO.StreamReader($r.GetResponseStream());try{$h=$sr.ReadToEnd()|ConvertFrom-Json}finally{$sr.Dispose()};if($h.service -cne 'uea-readonly-coordinator-v04' -or $h.mode -cne 'owner_policy_required_no_public_jobs'){throw 'CLOUD_CAPABILITY_SHAPE_UNEXPECTED'}}finally{$r.Dispose()}
 $null=Protect-CmsMessage -To $cert -Content 'UEA_INSTALL_CMS_ENCRYPTION_PROBE' -ErrorAction Stop
 [IO.Directory]::CreateDirectory((Split-Path -Parent $root))|Out-Null
 [IO.Directory]::CreateDirectory($root)|Out-Null;$created=$true
 Copy-Item -LiteralPath $program -Destination (Join-Path $root 'Run-UEAReadOnly.ps1') -ErrorAction Stop
 Copy-Item -LiteralPath $cert -Destination (Join-Path $root 'recipient.cer') -ErrorAction Stop
 if((Get-FileHash (Join-Path $root 'Run-UEAReadOnly.ps1') -Algorithm SHA256).Hash -cne '__AGENT_SOURCE_SHA256__'){throw 'COPY_INTEGRITY_FAILURE'}
 $ownerKeyName='UEA-ReadOnlyOwner-'+[guid]::NewGuid().ToString('N')
 $csp=[Security.Cryptography.CspParameters]::new(24,'Microsoft Enhanced RSA and AES Cryptographic Provider',$ownerKeyName)
 $csp.Flags=[Security.Cryptography.CspProviderFlags]::UseNonExportableKey
 $ownerRsa=[Security.Cryptography.RSACryptoServiceProvider]::new(2048,$csp);$ownerRsa.PersistKeyInCsp=$true
 if($ownerRsa.KeySize -ne 2048){throw 'OWNER_KEY_SIZE_UNEXPECTED'}
 $pub=$ownerRsa.ExportParameters($false)
 $ownerPub=[ordered]@{kty='RSA';e=(Url64 $pub.Exponent);n=(Url64 $pub.Modulus);alg='RS256';ext=$true}
 $now=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds();$expires=([DateTimeOffset]::UtcNow.AddDays(90)).ToUnixTimeMilliseconds()
 $policy=[ordered]@{version=1;revision=1;device_id=$device.device_id;root_id='workyard_mcp';root_path=$allowRoot;operations=@('inventory','read_file');max_file_bytes=32768;issued_ms=$now;expires_ms=$expires;recipient_cert_sha256='__RECIPIENT_CERT_SHA256_LOWER__'}
 $policyJson=ConvertTo-Json -InputObject $policy -Depth 6 -Compress
 $sig=$ownerRsa.SignData([Text.Encoding]::UTF8.GetBytes($policyJson),[Security.Cryptography.CryptoConfig]::MapNameToOID('SHA256'))
 $grant=[ordered]@{schema=1;policy_json=$policyJson;signature_b64=[Convert]::ToBase64String($sig);owner_public_jwk=$ownerPub}
 [IO.File]::WriteAllText((Join-Path $root 'owner-grant.json'),(ConvertTo-Json -InputObject $grant -Depth 8 -Compress),(New-Object Text.UTF8Encoding($false)))
 $ownerRsa.Dispose();$ownerRsa=$null
 # Self-test includes native verification of owner signature, root scope and CMS certificate.
  $selfResult=@(& (Join-Path $root 'Run-UEAReadOnly.ps1') -SelfTest)
 if($selfResult -notcontains 'UEA_RO_SELFTEST_PASSED'){throw 'AGENT_SELFTEST_CHILD_FAILED'}
 $ps=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
 $vbs=Join-Path $root 'RunHidden.vbs'
 $arg='"'+$ps+'" -NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "'+(Join-Path $root 'Run-UEAReadOnly.ps1')+'" -FromTask'
 $content='Set sh = CreateObject("WScript.Shell")'+[Environment]::NewLine+'Dim result'+[Environment]::NewLine+'result = sh.Run("'+$arg.Replace('"','""')+'", 0, True)'+[Environment]::NewLine+'WScript.Quit result'+[Environment]::NewLine
 [IO.File]::WriteAllText($vbs,$content,(New-Object Text.UTF8Encoding($false)))
 $user=[Security.Principal.WindowsIdentity]::GetCurrent().Name
 $trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 3650)
 $logon=New-ScheduledTaskTrigger -AtLogOn -User $user
 $action=New-ScheduledTaskAction -Execute (Join-Path $env:WINDIR 'System32\wscript.exe') -Argument ('"'+$vbs+'"')
 $principal=New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
 $settings=New-ScheduledTaskSettingsSet -Hidden -MultipleInstances IgnoreNew -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 4) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
 Register-ScheduledTask -TaskName $taskName -Action $action -Trigger @($trigger,$logon) -Principal $principal -Settings $settings -Description 'Universal owner-signed read-only source inspection, encrypted to pinned recipient; no writes' -ErrorAction Stop|Out-Null
 $taskCreated=$true
 $got=Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
 if(-not $got.Settings.Hidden -or @($got.Triggers).Count -ne 2){throw 'TASK_READBACK_FAILED'}
 $mark=Join-Path $root 'task-started.txt';$started=[DateTime]::UtcNow
 Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
 $deadline=$started.AddSeconds(75);$seen=$false
 while([DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 600;if(Test-Path -LiteralPath $mark -PathType Leaf){$x=Get-Item -LiteralPath $mark;if($x.LastWriteTimeUtc -ge $started.AddSeconds(-2)){$seen=$true;break}}}
 if(-not $seen){throw 'TASK_CHILD_STARTUP_NOT_VERIFIED'}
 $native=Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
 Write-Host 'UEA_READONLY_INSTALL_VERIFIED'
 Write-Host ('UEA_DEVICE_ID='+$device.device_id)
 Write-Host ('UEA_SIGNED_POLICY_ROOT='+$allowRoot)
 Write-Host ('UEA_POLICY_EXPIRES_UTC='+([DateTimeOffset]::FromUnixTimeMilliseconds($expires)).UtcDateTime.ToString('o'))
 Write-Host 'UEA_AGENT_OPERATIONS=INVENTORY,READ_FILE_ONLY'
 Write-Host 'UEA_BUSINESS_WRITES=DISABLED'
 Write-Host 'UEA_EXISTING_HEARTBEAT_PRESERVED=YES'
 if($native){Write-Host ('UEA_SCHEDULED_LAST_RESULT='+[string]$native.LastTaskResult)}
}catch {
 $msg=$_.Exception.Message
 if($taskCreated){try{Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop}catch{Write-Host 'UEA_RO_CLEANUP_TASK_FAILED_REVIEW'}}
 $left=[bool](Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)
 if($ownerRsa){$ownerRsa.Dispose()}
 if(-not $left){
   if($ownerKeyName){try{$p=[Security.Cryptography.CspParameters]::new(24,'Microsoft Enhanced RSA and AES Cryptographic Provider',$ownerKeyName);$p.Flags=[Security.Cryptography.CspProviderFlags]::UseExistingKey;$k=[Security.Cryptography.RSACryptoServiceProvider]::new(2048,$p);$k.PersistKeyInCsp=$false;$k.Clear()}catch{}}
   if($created){Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue}
 }else{Write-Host 'UEA_READONLY_TASK_REMAINS=YES; PRESERVED FOR REVIEW'}
 Write-Host ('UEA_RO_INSTALL_ABORTED='+$msg)
 throw
}