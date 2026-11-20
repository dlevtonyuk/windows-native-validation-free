$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$original=$env:LOCALAPPDATA
$base=Join-Path $env:RUNNER_TEMP ('uea-v041-test-'+[guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($base)|Out-Null
$env:LOCALAPPDATA=$base
$hb=Join-Path $base 'ChatGPT\UEA-DeviceAgent';$ro=Join-Path $base 'ChatGPT\UEA-ReadOnlyAgent';$source=Join-Path $base 'UEA-Synthetic-TestRoot'
@($hb,$ro,$source)|ForEach-Object{[IO.Directory]::CreateDirectory($_)|Out-Null}
$taskPath=Join-Path $ro 'Run-UEAReadOnly.ps1'
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Run-UEAReadOnly-SYNTHETIC-DIAG.ps1') -Destination $taskPath
$cert=$null;$rsa=$null;$keyname=$null
function Url64([byte[]]$b){[Convert]::ToBase64String($b).TrimEnd('=').Replace('+','-').Replace('/','_')}
try {
  $device='dev_'+([guid]::NewGuid().ToString('N'))
  $idname='UEA-DeviceIdentity-'+([guid]::NewGuid().ToString('N'))
  $idconfig=[ordered]@{version=1;device_id=$device;key_container=$idname;endpoint='https://example.invalid';public_jwk=@{}}
  [IO.File]::WriteAllText((Join-Path $hb 'device-public.json'),(ConvertTo-Json -InputObject $idconfig -Depth 8 -Compress))
  $cert=New-SelfSignedCertificate -Type DocumentEncryptionCert -Subject 'CN=UEA Synthetic 041' -CertStoreLocation 'Cert:\CurrentUser\My'
  if(-not $cert){throw 'TEST_CERT_CREATE_FAILED'}
  $recipient=Join-Path $ro 'recipient.cer'
  Export-Certificate -Cert $cert -FilePath $recipient -Force|Out-Null
  $hash=(Get-FileHash -LiteralPath $recipient -Algorithm SHA256).Hash.ToLowerInvariant()
  $keyname='UEA-ReadOnlyOwner-'+[guid]::NewGuid().ToString('N')
  $csp=[Security.Cryptography.CspParameters]::new(24,'Microsoft Enhanced RSA and AES Cryptographic Provider',$keyname)
  $csp.Flags=[Security.Cryptography.CspProviderFlags]::UseNonExportableKey
  $rsa=[Security.Cryptography.RSACryptoServiceProvider]::new(2048,$csp);$rsa.PersistKeyInCsp=$true
  $pub=$rsa.ExportParameters($false)
  $jwk=[ordered]@{kty='RSA';e=(Url64 $pub.Exponent);n=(Url64 $pub.Modulus);alg='RS256';ext=$true}
  $now=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds();$exp=([DateTimeOffset]::UtcNow.AddDays(1)).ToUnixTimeMilliseconds()
  $policy=[ordered]@{version=1;revision=1;device_id=$device;root_id='synthetic_root';root_path=$source;operations=@('inventory','read_file');max_file_bytes=32768;issued_ms=$now;expires_ms=$exp;recipient_cert_sha256=$hash}
  $json=ConvertTo-Json -InputObject $policy -Depth 6 -Compress
  $sig=$rsa.SignData([Text.Encoding]::UTF8.GetBytes($json),[Security.Cryptography.CryptoConfig]::MapNameToOID('SHA256'))
  $grant=[ordered]@{schema=1;policy_json=$json;signature_b64=[Convert]::ToBase64String($sig);owner_public_jwk=$jwk}
  [IO.File]::WriteAllText((Join-Path $ro 'owner-grant.json'),(ConvertTo-Json -InputObject $grant -Depth 8 -Compress))
  $rsa.Dispose();$rsa=$null
  Write-Host 'UEA_SYNTHETIC_REPRO_START'
  $captured=@(& $taskPath -SelfTest)
  if($captured -notcontains 'UEA_RO_SELFTEST_PASSED'){throw 'OUTPUT_CONTRACT_FAILED'}
  Write-Host 'UEA_SELFTEST_CAPTURE_CONTRACT_PASSED'
  Write-Host 'UEA_SYNTHETIC_SELFTEST_SUCCEEDED'
}catch{
  Write-Host ('UEA_SYNTHETIC_CHILD_FAILURE_CODE='+$_.Exception.Message)
  throw
}finally{
  $env:LOCALAPPDATA=$original
  if($rsa){$rsa.Dispose()}
  if($keyname){try{$c=[Security.Cryptography.CspParameters]::new(24,'Microsoft Enhanced RSA and AES Cryptographic Provider',$keyname);$c.Flags=[Security.Cryptography.CspProviderFlags]::UseExistingKey;$k=[Security.Cryptography.RSACryptoServiceProvider]::new(2048,$c);$k.PersistKeyInCsp=$false;$k.Clear()}catch{}}
  if($cert){Remove-Item -LiteralPath ('Cert:\CurrentUser\My\'+$cert.Thumbprint) -Force -ErrorAction SilentlyContinue}
  if(Test-Path -LiteralPath $base){Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction SilentlyContinue}
}