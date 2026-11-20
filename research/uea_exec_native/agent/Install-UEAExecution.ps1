#requires -Version 5.1
# Install UEA v0.5 as a separate, reversible, non-admin, owner-granted package executor.
# One signed approved diagnostic only. Never modify previous heartbeat/read-only tasks.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$src=Split-Path -Parent $MyInvocation.MyCommand.Path
$root=Join-Path $env:LOCALAPPDATA 'ChatGPT\UEA-ExecutionAgent'
$hbRoot=Join-Path $env:LOCALAPPDATA 'ChatGPT\UEA-DeviceAgent'
$roRoot=Join-Path $env:LOCALAPPDATA 'ChatGPT\UEA-ReadOnlyAgent'
$taskName='ChatGPT UEA Device Agent - ApprovedExec'
$heartbeatName='ChatGPT UEA Device Agent - Heartbeat'
$readOnlyName='ChatGPT UEA Device Agent - ReadOnly'
$health='https://uag-execution-v05.dlevtonyuk.workers.dev/health'
$created=$false;$taskCreated=$false;$ownerRsa=$null;$ownerName=$null
function Url64([byte[]]$b){return [Convert]::ToBase64String($b).TrimEnd('=').Replace('+','-').Replace('/','_')}
try {
 if($env:OS -ne 'Windows_NT' -or $PSVersionTable.PSVersion.Major -ne 5){throw 'WINDOWS_POWERSHELL_5_1_REQUIRED'}
 if([Security.Principal.WindowsIdentity]::GetCurrent().IsSystem){throw 'SYSTEM_ACCOUNT_DENIED'}
 if(Test-Path -LiteralPath $root){throw 'EXEC_AGENT_ALREADY_EXISTS_PRESERVE_ORIGINAL'}
 if(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue){throw 'EXEC_TASK_ALREADY_EXISTS_PRESERVE_ORIGINAL'}
 if(-not(Get-ScheduledTask -TaskName $heartbeatName -ErrorAction SilentlyContinue)){throw 'ORIGINAL_HEARTBEAT_TASK_MISSING'}
 if(-not(Get-ScheduledTask -TaskName $readOnlyName -ErrorAction SilentlyContinue)){throw 'READONLY_AGENT_TASK_MISSING'}
 if(-not(Test-Path -LiteralPath $roRoot -PathType Container)){throw 'READONLY_AGENT_FOLDER_MISSING'}
 $devicePath=Join-Path $hbRoot 'device-public.json';if(-not(Test-Path -LiteralPath $devicePath -PathType Leaf)){throw 'DEVICE_IDENTITY_UNAVAILABLE'}
 $identity=Get-Content -LiteralPath $devicePath -Raw|ConvertFrom-Json
 if($identity.version -ne 1 -or $identity.device_id -notmatch '^dev_[a-f0-9]{32}$' -or $identity.key_container -notmatch '^UEA-DeviceIdentity-[a-f0-9]{32}$'){throw 'IDENTITY_BAD_FORMAT'}
 $script=Join-Path $src 'Run-UEAExec.ps1';$package=Join-Path $src 'UEA-Diagnostic-v1.ps1';$certificate=Join-Path $src 'recipient.cer'
 foreach($f in @($script,$package,$certificate)){if(-not(Test-Path -LiteralPath $f -PathType Leaf)){throw 'SIGNED_RELEASE_FILES_MISSING'}}
 if((Get-FileHash -LiteralPath $script -Algorithm SHA256).Hash -cne '975B8AAA8D61FFEF7E7FC321D6BA29B74208A947FA256339DC2B6C161314960E'){throw 'EXEC_AGENT_HASH_INVALID'}
 if((Get-FileHash -LiteralPath $package -Algorithm SHA256).Hash -cne '606E8821DAB8489D54722212FB8B20A3DF30F15DED23688F49E43BFCC6A84335'){throw 'EXEC_PACKAGE_HASH_INVALID'}
 if((Get-FileHash -LiteralPath $certificate -Algorithm SHA256).Hash -cne 'B324F73F0D1188DCF8A4D051FA4FD68CC1FA8ECF5356F9DE1F66E283D20BF560'){throw 'CMS_CERT_HASH_INVALID'}
 [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
 $req=[Net.HttpWebRequest][Net.WebRequest]::Create($health);$req.AllowAutoRedirect=$false;$req.Timeout=12000
 $resp=[Net.HttpWebResponse]$req.GetResponse()
 try{if([int]$resp.StatusCode -ne 200){throw 'CLOUD_ENDPOINT_BAD_STATUS'};$rd=New-Object IO.StreamReader($resp.GetResponseStream());try{$h=$rd.ReadToEnd()|ConvertFrom-Json}finally{$rd.Dispose()};if($h.service -cne 'uea-exec-v05' -or $h.mode -cne 'owner_local_approval_required_no_public_jobs'){throw 'CLOUD_CAPABILITY_MISMATCH'}}finally{$resp.Dispose()}
 $probe=Protect-CmsMessage -To $certificate -Content 'UEA_EXEC_PILOT_ENCRYPTION_TEST' -ErrorAction Stop
 if($probe -notmatch 'BEGIN CMS'){throw 'CMS_PREFLIGHT_FAILED'}
 [IO.Directory]::CreateDirectory($root)|Out-Null;$created=$true
 [IO.Directory]::CreateDirectory((Join-Path $root 'packages'))|Out-Null
 Copy-Item -LiteralPath $script -Destination (Join-Path $root 'Run-UEAExec.ps1')
 Copy-Item -LiteralPath $package -Destination (Join-Path (Join-Path $root 'packages') 'UEA-Diagnostic-v1.ps1')
 Copy-Item -LiteralPath $certificate -Destination (Join-Path $root 'recipient.cer')
 if((Get-FileHash -LiteralPath (Join-Path $root 'Run-UEAExec.ps1') -Algorithm SHA256).Hash -cne '975B8AAA8D61FFEF7E7FC321D6BA29B74208A947FA256339DC2B6C161314960E'){throw 'COPIED_AGENT_CHANGED'}
 if((Get-FileHash -LiteralPath (Join-Path $root 'packages\UEA-Diagnostic-v1.ps1') -Algorithm SHA256).Hash -cne '606E8821DAB8489D54722212FB8B20A3DF30F15DED23688F49E43BFCC6A84335'){throw 'COPIED_PACKAGE_CHANGED'}
 $ownerName='UEA-ExecOwner-'+[guid]::NewGuid().ToString('N')
 $csp=[Security.Cryptography.CspParameters]::new(24,'Microsoft Enhanced RSA and AES Cryptographic Provider',$ownerName)
 $csp.Flags=[Security.Cryptography.CspProviderFlags]::UseNonExportableKey
 $ownerRsa=[Security.Cryptography.RSACryptoServiceProvider]::new(2048,$csp);$ownerRsa.PersistKeyInCsp=$true
 if($ownerRsa.KeySize -ne 2048){throw 'OWNER_KEY_GENERATION_FAILED'}
 $public=$ownerRsa.ExportParameters($false)
 $jwk=[ordered]@{kty='RSA';e=(Url64 $public.Exponent);n=(Url64 $public.Modulus);alg='RS256';ext=$true}
 $now=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds();$expiry=[DateTimeOffset]::UtcNow.AddDays(90).ToUnixTimeMilliseconds()
 $policy=[ordered]@{version=1;revision=1;device_id=$identity.device_id;capability='execute_approved_package';max_output_bytes=8192;max_runtime_seconds=45;issued_ms=$now;expires_ms=$expiry;recipient_cert_sha256='b324f73f0d1188dcf8a4d051fa4fd68cc1fa8ecf5356f9de1f66e283d20bf560';packages=@([ordered]@{package_id='uea_diagnostic_v1';package_sha256='606e8821dab8489d54722212fb8b20a3df30f15ded23688f49e43bfcc6a84335';filename='UEA-Diagnostic-v1.ps1';effect='none'})}
 $json=ConvertTo-Json -InputObject $policy -Depth 9 -Compress
 $sig=$ownerRsa.SignData([Text.Encoding]::UTF8.GetBytes($json),[Security.Cryptography.CryptoConfig]::MapNameToOID('SHA256'))
 $ownerGrant=[ordered]@{schema=1;policy_json=$json;signature_b64=[Convert]::ToBase64String($sig);owner_public_jwk=$jwk}
 [IO.File]::WriteAllText((Join-Path $root 'owner-grant.json'),(ConvertTo-Json -InputObject $ownerGrant -Depth 10 -Compress),(New-Object Text.UTF8Encoding($false)))
 $ownerRsa.Dispose();$ownerRsa=$null
 $self=@(& (Join-Path $root 'Run-UEAExec.ps1') -SelfTest)
 if($self -notcontains 'UEA_EXEC_SELFTEST_OK'){throw 'EXEC_SELFTEST_OUTPUT_INVALID'}
 Write-Host 'UEA_EXEC_LOCAL_SIGNED_CHILD_SELFTEST_PASSED'
 $ps=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
 $vbs=Join-Path $root 'RunHidden.vbs'
 $command='"'+$ps+'" -NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "'+(Join-Path $root 'Run-UEAExec.ps1')+'" -FromTask'
 $vbsScript='Set sh = CreateObject("WScript.Shell")'+[Environment]::NewLine+'Dim ret'+[Environment]::NewLine+'ret=sh.Run("'+$command.Replace('"','""')+'",0,True)'+[Environment]::NewLine+'WScript.Quit ret'+[Environment]::NewLine
 [IO.File]::WriteAllText($vbs,$vbsScript,(New-Object Text.UTF8Encoding($false)))
 $user=[Security.Principal.WindowsIdentity]::GetCurrent().Name
 $repeat=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 3650)
 $logon=New-ScheduledTaskTrigger -AtLogOn -User $user
 $action=New-ScheduledTaskAction -Execute (Join-Path $env:WINDIR 'System32\wscript.exe') -Argument ('"'+$vbs+'"')
 $principal=New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
 $settings=New-ScheduledTaskSettingsSet -Hidden -MultipleInstances IgnoreNew -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 3) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
 Register-ScheduledTask -TaskName $taskName -Action $action -Trigger @($repeat,$logon) -Principal $principal -Settings $settings -Description 'UEA v0.5 owner-signed, hash-pinned, non-privileged approved diagnostic execution only; no business writes' -ErrorAction Stop|Out-Null
 $taskCreated=$true
 $installed=Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
 if(-not $installed.Settings.Hidden -or @($installed.Triggers).Count -ne 2){throw 'EXEC_SCHEDULER_READBACK_FAILED'}
 $marker=Join-Path $root 'task-started.txt';$start=[DateTime]::UtcNow
 Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
 $deadline=$start.AddSeconds(75);$found=$false
 while([DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 600;if(Test-Path -LiteralPath $marker -PathType Leaf){$entry=Get-Item -LiteralPath $marker;if($entry.LastWriteTimeUtc -ge $start.AddSeconds(-2)){$found=$true;break}}}
 if(-not $found){throw 'EXEC_TASK_CHILD_STARTUP_UNVERIFIED'}
 if(-not(Get-ScheduledTask -TaskName $heartbeatName -ErrorAction SilentlyContinue) -or -not(Get-ScheduledTask -TaskName $readOnlyName -ErrorAction SilentlyContinue)){throw 'PREVIOUS_TASKS_CHANGED'}
 $task=Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
 Write-Host 'UEA_EXEC_INSTALL_VERIFIED'
 Write-Host ('UEA_DEVICE_ID='+$identity.device_id)
 Write-Host 'UEA_APPROVED_PACKAGE=uea_diagnostic_v1'
 Write-Host 'UEA_EXECUTION_GRANT=SIGNED_LOCAL_ONE_PACKAGE_ONLY'
 Write-Host 'UEA_UNAUTHORIZED_COMMANDS=DENIED'
 Write-Host 'UEA_BUSINESS_WRITES=DISABLED'
 Write-Host 'UEA_EXISTING_TASKS_PRESERVED=HEARTBEAT,READONLY'
 Write-Host ('UEA_EXEC_POLICY_EXPIRES_UTC='+([DateTimeOffset]::FromUnixTimeMilliseconds($expiry)).UtcDateTime.ToString('o'))
 if($task){Write-Host ('UEA_EXEC_TASK_LAST_RESULT='+[string]$task.LastTaskResult)}
}catch{
 $reason=$_.Exception.Message
 if($taskCreated){try{Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop}catch{Write-Host 'UEA_EXEC_CLEANUP_TASK_FAILED_MANUAL_REVIEW'}}
 $still=[bool](Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)
 if($ownerRsa){$ownerRsa.Dispose()}
 if(-not $still){
  if($ownerName){try{$cp=[Security.Cryptography.CspParameters]::new(24,'Microsoft Enhanced RSA and AES Cryptographic Provider',$ownerName);$cp.Flags=[Security.Cryptography.CspProviderFlags]::UseExistingKey;$key=[Security.Cryptography.RSACryptoServiceProvider]::new(2048,$cp);$key.PersistKeyInCsp=$false;$key.Clear()}catch{}}
  if($created){Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue}
 }else{Write-Host 'UEA_EXEC_NEW_TASK_STILL_PRESENT_PRESERVED_FOR_REVIEW'}
 Write-Host ('UEA_EXEC_INSTALL_ABORTED='+$reason)
 throw
}