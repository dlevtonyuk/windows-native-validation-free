# Disposable synthetic fixture: NEVER accesses a customer's device/files/accounts.
# Must run as Windows PowerShell 5.1 on isolated GitHub-hosted Windows runner.
#requires -Version 5.1
[CmdletBinding()]
param()
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$original=$env:LOCALAPPDATA
$here=Split-Path -Parent $MyInvocation.MyCommand.Path
$packageDir=Resolve-Path (Join-Path $here '..\agent')
$fixture=Join-Path $env:TEMP ('UEA-exec-test-'+[guid]::NewGuid().ToString('N'))
$certObject=$null;$identityKey=$null;$ownerKey=$null;$deviceKeyName=$null;$ownerKeyName=$null;$tests=0
function Check([bool]$condition,[string]$id){if(-not $condition){throw ('TEST_FAIL_'+$id)};$script:tests++}
function Url64([byte[]]$data){return [Convert]::ToBase64String($data).TrimEnd('=').Replace('+','-').Replace('/','_')}
function OpenKey([string]$name){$c=[Security.Cryptography.CspParameters]::new(24,'Microsoft Enhanced RSA and AES Cryptographic Provider',$name);$c.Flags=[Security.Cryptography.CspProviderFlags]::UseNonExportableKey;return [Security.Cryptography.RSACryptoServiceProvider]::new(2048,$c)}
function RunSelfTest([string]$scriptPath){
 $cmd=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
 $p=New-Object Diagnostics.ProcessStartInfo
 $p.FileName=$cmd;$p.Arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$scriptPath+'" -SelfTest';$p.RedirectStandardOutput=$true;$p.RedirectStandardError=$true;$p.UseShellExecute=$false;$p.CreateNoWindow=$true
 $proc=[Diagnostics.Process]::Start($p)
 try{$out=$proc.StandardOutput.ReadToEnd();$err=$proc.StandardError.ReadToEnd();if(-not $proc.WaitForExit(60000)){$proc.Kill();throw 'SELFTEST_TIMEOUT'};return @{exit=$proc.ExitCode;out=$out;err=$err}}finally{$proc.Dispose()}
}
try{
 Check ($env:OS -eq 'Windows_NT' -and $PSVersionTable.PSVersion.Major -eq 5) 'NATIVE_WINDOWS_51'
 if($env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'HOSTED_RUNNER_ONLY'}
 [IO.Directory]::CreateDirectory($fixture)|Out-Null;$env:LOCALAPPDATA=$fixture
 $hb=Join-Path $fixture 'ChatGPT\UEA-DeviceAgent';$root=Join-Path $fixture 'ChatGPT\UEA-ExecutionAgent'
 [IO.Directory]::CreateDirectory($hb)|Out-Null;[IO.Directory]::CreateDirectory((Join-Path $root 'packages'))|Out-Null
 $deviceId='dev_'+[guid]::NewGuid().ToString('N');$deviceKeyName='UEA-DeviceIdentity-'+[guid]::NewGuid().ToString('N')
 $identityKey=OpenKey $deviceKeyName;$identityKey.PersistKeyInCsp=$true
 $id=[ordered]@{version=1;device_id=$deviceId;key_container=$deviceKeyName}
 [IO.File]::WriteAllText((Join-Path $hb 'device-public.json'),(ConvertTo-Json -InputObject $id -Compress))
 Copy-Item -LiteralPath (Join-Path $packageDir 'Run-UEAExec.ps1') -Destination (Join-Path $root 'Run-UEAExec.ps1')
 $certObject=New-SelfSignedCertificate -Type DocumentEncryptionCert -Subject 'CN=UEA Synthetic Native Test Recipient' -CertStoreLocation 'Cert:\CurrentUser\My'
 Export-Certificate -Cert $certObject -FilePath (Join-Path $root 'recipient.cer') -Force | Out-Null
 Copy-Item -LiteralPath (Join-Path $packageDir 'UEA-Diagnostic-v1.ps1') -Destination (Join-Path $root 'packages\UEA-Diagnostic-v1.ps1')
 $agent=Join-Path $root 'Run-UEAExec.ps1';$pkg=Join-Path $root 'packages\UEA-Diagnostic-v1.ps1'
 $sha=(Get-FileHash -LiteralPath $pkg -Algorithm SHA256).Hash.ToLowerInvariant()
 Check ($sha -eq '606e8821dab8489d54722212fb8b20a3df30f15ded23688f49e43bfcc6a84335') 'PACKAGE_PIN'
 $ownerKeyName='UEA-ExecOwner-'+[guid]::NewGuid().ToString('N');$ownerKey=OpenKey $ownerKeyName;$ownerKey.PersistKeyInCsp=$true
 $pub=$ownerKey.ExportParameters($false);$jwk=[ordered]@{kty='RSA';e=(Url64 $pub.Exponent);n=(Url64 $pub.Modulus);alg='RS256';ext=$true}
 $now=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
 $certDigest=(Get-FileHash -LiteralPath (Join-Path $root 'recipient.cer') -Algorithm SHA256).Hash.ToLowerInvariant()
 $policy=[ordered]@{version=1;revision=1;device_id=$deviceId;capability='execute_approved_package';max_output_bytes=8192;max_runtime_seconds=45;issued_ms=$now;expires_ms=($now+3600000);recipient_cert_sha256=$certDigest;packages=@([ordered]@{package_id='uea_diagnostic_v1';package_sha256=$sha;filename='UEA-Diagnostic-v1.ps1';effect='none'})}
 $policyJson=ConvertTo-Json -InputObject $policy -Depth 10 -Compress
 $sig=$ownerKey.SignData([Text.Encoding]::UTF8.GetBytes($policyJson),[Security.Cryptography.CryptoConfig]::MapNameToOID('SHA256'))
 $grant=[ordered]@{schema=1;policy_json=$policyJson;signature_b64=[Convert]::ToBase64String($sig);owner_public_jwk=$jwk}
 $grantPath=Join-Path $root 'owner-grant.json'
 [IO.File]::WriteAllText($grantPath,(ConvertTo-Json -InputObject $grant -Depth 10 -Compress))
 $ownerKey.Dispose();$ownerKey=$null;$identityKey.Dispose();$identityKey=$null
 $run=RunSelfTest $agent
 if($run.exit -ne 0){Write-Host ('AGENT_STDOUT='+$run.out);Write-Host ('AGENT_STDERR='+$run.err)}
 Check ($run.exit -eq 0) 'SELFTEST_EXIT'
 Check ($run.out -match 'UEA_EXEC_SELFTEST_OK') 'CHILD_EXECUTION_VERIFIED'
 Check ($run.err.Trim().Length -eq 0) 'NO_STDERR'
 $grantBackup=Get-Content -LiteralPath $grantPath -Raw
 $tampered=$grantBackup|ConvertFrom-Json;$tampered.policy_json=$tampered.policy_json.Replace('8192','8193')
 [IO.File]::WriteAllText($grantPath,(ConvertTo-Json -InputObject $tampered -Depth 10 -Compress))
 $test=RunSelfTest $agent
 Check ($test.exit -ne 0) 'SIGNATURE_TAMPER_DENIED'
 [IO.File]::WriteAllText($grantPath,$grantBackup)
 Add-Content -LiteralPath $pkg -Value '# unauthorized modification'
 $test=RunSelfTest $agent
 Check ($test.exit -ne 0) 'PACKAGE_HASH_TAMPER_DENIED'
 Write-Host ('UEA_EXEC_NATIVE_TESTS_PASSED='+$tests)
}finally{
 $env:LOCALAPPDATA=$original
 if($certObject){Remove-Item -LiteralPath ('Cert:\CurrentUser\My\'+$certObject.Thumbprint) -Force -ErrorAction SilentlyContinue}
 if($ownerKey){$ownerKey.Dispose()};if($identityKey){$identityKey.Dispose()}
 foreach($name in @($ownerKeyName,$deviceKeyName)){
  if($name){try{$cp=[Security.Cryptography.CspParameters]::new(24,'Microsoft Enhanced RSA and AES Cryptographic Provider',$name);$cp.Flags=[Security.Cryptography.CspProviderFlags]::UseExistingKey;$k=[Security.Cryptography.RSACryptoServiceProvider]::new(2048,$cp);$k.PersistKeyInCsp=$false;$k.Clear()}catch{}}
 }
 if(Test-Path -LiteralPath $fixture){Remove-Item -LiteralPath $fixture -Recurse -Force -ErrorAction SilentlyContinue}
}