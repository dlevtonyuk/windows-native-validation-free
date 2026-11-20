#requires -Version 5.1
# UEA v0.5 generic agent: ONLY locally owner-authorized hash-pinned packages.
# No arbitrary cloud commands, dynamic code, credentials, file download, or business writes.
[CmdletBinding()]
param([switch]$FromTask,[switch]$SelfTest)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$base=Split-Path -Parent $MyInvocation.MyCommand.Path
$hbBase=Join-Path $env:LOCALAPPDATA 'ChatGPT\UEA-DeviceAgent'
$CLOUD='https://uag-execution-v05.dlevtonyuk.workers.dev'

function Hex([byte[]]$bytes){return ([BitConverter]::ToString($bytes)).Replace('-','').ToLowerInvariant()}

function Digest([byte[]]$bytes){$h=[Security.Cryptography.SHA256]::Create();try{return (Hex ($h.ComputeHash($bytes)))}finally{$h.Dispose()}}

function Base64UrlDecode([string]$s){if($s -notmatch '^[A-Za-z0-9_-]{1,512}$'){throw 'INVALID_PUBLIC_KEY'};$v=$s.Replace('-','+').Replace('_','/');switch($v.Length%4){2{$v+='=='}3{$v+='='}0{}default{throw 'INVALID_KEY_ENCODING'}};return [Convert]::FromBase64String($v)}

function Open-CspKey([string]$name){if($name -notmatch '^UEA-(DeviceIdentity|ReadOnlyOwner)-[a-f0-9]{32}$'){throw 'INVALID_KEY_CONTAINER'};$p=[Security.Cryptography.CspParameters]::new(24,'Microsoft Enhanced RSA and AES Cryptographic Provider',$name);$p.Flags=[Security.Cryptography.CspProviderFlags]::UseExistingKey;$key=[Security.Cryptography.RSACryptoServiceProvider]::new(2048,$p);if($key.PublicOnly -or $key.KeySize -ne 2048){$key.Dispose();throw 'KEY_UNAVAILABLE'};return $key}

function PublicKey([object]$jwk){
 if($jwk.kty -cne 'RSA' -or $jwk.alg -cne 'RS256' -or $jwk.ext -cne $true -or $jwk.e -cne 'AQAB'){throw 'BAD_PUBLIC_KEY'}
 $params=New-Object Security.Cryptography.RSAParameters
 $params.Modulus=Base64UrlDecode ([string]$jwk.n);$params.Exponent=Base64UrlDecode ([string]$jwk.e)
 if($params.Modulus.Length -ne 256){throw 'BAD_RSA_MODULUS'}
 $rsa=[Security.Cryptography.RSACryptoServiceProvider]::new();$rsa.PersistKeyInCsp=$false;$rsa.ImportParameters($params);return $rsa
}

function Verify-LocalGrant {
 $grantPath=Join-Path $base 'owner-grant.json'
 if(-not(Test-Path -LiteralPath $grantPath -PathType Leaf)){throw 'OWNER_GRANT_MISSING'}
 $grant=Get-Content -LiteralPath $grantPath -Raw|ConvertFrom-Json
 if($grant.schema -ne 1 -or -not $grant.policy_json -or -not $grant.signature_b64){throw 'OWNER_GRANT_SHAPE'}
 $p=$grant.policy_json|ConvertFrom-Json
 if($p.version -ne 1 -or $p.revision -ne 1 -or $p.capability -cne 'execute_approved_package' -or $p.device_id -notmatch '^dev_[a-f0-9]{32}$'){throw 'OWNER_GRANT_INVALID'}
 $now=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
 if([long]$p.expires_ms -le $now -or [long]$p.issued_ms -gt $now+120000){throw 'OWNER_GRANT_EXPIRED_OR_FUTURE'}
 if($p.max_output_bytes -ne 8192 -or $p.max_runtime_seconds -ne 45){throw 'OWNER_LIMITS_INVALID'}
 if(@($p.packages).Count -ne 1){throw 'OWNER_PACKAGE_COUNT_INVALID'}
 $a=@($p.packages)[0]
 if($a.package_id -cne 'uea_diagnostic_v1' -or $a.package_sha256 -notmatch '^[a-f0-9]{64}$' -or $a.filename -cne 'UEA-Diagnostic-v1.ps1' -or $a.effect -cne 'none'){throw 'OWNER_PACKAGE_INVALID'}
 $hbPath=Join-Path $hbBase 'device-public.json'
 if(-not(Test-Path -LiteralPath $hbPath -PathType Leaf)){throw 'DEVICE_IDENTITY_MISSING'}
 $identity=Get-Content -LiteralPath $hbPath -Raw|ConvertFrom-Json
 if($identity.device_id -cne $p.device_id -or $identity.key_container -notmatch '^UEA-DeviceIdentity-[a-f0-9]{32}$'){throw 'DEVICE_IDENTITY_CHANGED'}
 $ownerRsa=PublicKey $grant.owner_public_jwk
 try{
  $sig=[Convert]::FromBase64String([string]$grant.signature_b64)
  if($sig.Length -ne 256 -or -not $ownerRsa.VerifyData([Text.Encoding]::UTF8.GetBytes([string]$grant.policy_json),[Security.Cryptography.CryptoConfig]::MapNameToOID('SHA256'),$sig)){throw 'OWNER_SIGNED_POLICY_INVALID'}
 }finally{$ownerRsa.Dispose()}
 $cert=Join-Path $base 'recipient.cer'
 if(-not(Test-Path -LiteralPath $cert -PathType Leaf)){throw 'RECIPIENT_MISSING'}
 if((Get-FileHash -LiteralPath $cert -Algorithm SHA256).Hash.ToLowerInvariant() -cne $p.recipient_cert_sha256){throw 'RECIPIENT_CERT_CHANGED'}
 if(Test-Path -LiteralPath (Join-Path $base 'local-stop.flag') -PathType Leaf){throw 'OWNER_STOP_ACTIVE'}
 $script=Join-Path (Join-Path $base 'packages') ([string]$a.filename)
 if(-not(Test-Path -LiteralPath $script -PathType Leaf)){throw 'SIGNED_PACKAGE_MISSING'}
 foreach($v in @($base,(Join-Path $base 'packages'),$script)){
  if((Get-Item -LiteralPath $v -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'PACKAGE_REPARSE_DENIED'}
 }
 if((Get-FileHash -LiteralPath $script -Algorithm SHA256).Hash.ToLowerInvariant() -cne $a.package_sha256){throw 'SIGNED_PACKAGE_HASH_CHANGED'}
 return @{Policy=$p;Identity=$identity;Recipient=$cert;Script=$script;Allowed=$a}
}
function Run-ApprovedPackage([string]$script,[int]$limitSeconds,[int]$limitBytes){
 $psi=New-Object Diagnostics.ProcessStartInfo
 $psi.FileName=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
 if(-not(Test-Path -LiteralPath $psi.FileName -PathType Leaf)){throw 'SYSTEM_POWERSHELL_UNAVAILABLE'}
 $psi.Arguments='-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "'+$script+'"'
 $psi.UseShellExecute=$false;$psi.CreateNoWindow=$true
 $psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
 $psi.WorkingDirectory=$base
 $proc=New-Object Diagnostics.Process
 $proc.StartInfo=$psi
 try {
  if(-not $proc.Start()){throw 'CHILD_LAUNCH_FAILED'}
  $so=$proc.StandardOutput.ReadToEndAsync();$se=$proc.StandardError.ReadToEndAsync()
  if(-not $proc.WaitForExit($limitSeconds*1000)){
    try{$proc.Kill();$proc.WaitForExit(2000)|Out-Null}catch{}
    throw 'CHILD_TIMEOUT'
  }
  if(-not $so.Wait(5000) -or -not $se.Wait(5000)){throw 'CHILD_STREAM_TIMEOUT'}
  if($proc.ExitCode -ne 0){throw 'APPROVED_PACKAGE_EXIT_FAILURE'}
  $stdout=[string]$so.Result;$stderr=[string]$se.Result
  if($stderr.Trim().Length -gt 0){throw 'APPROVED_PACKAGE_STDERR_NONEMPTY'}
  if([Text.Encoding]::UTF8.GetByteCount($stdout) -gt $limitBytes){throw 'APPROVED_PACKAGE_OUTPUT_TOO_LARGE'}
  $read=$stdout.Trim()
  if($read -match '(?i)(?:password|private.key|api.key|access.token|bearer\s+[A-Za-z0-9])'){throw 'PACKAGE_OUTPUT_REDACTION_DENIED'}
  if($read -notmatch '"kind":"UEA_SIGNED_REMOTE_EXECUTION_PROOF"'){throw 'PACKAGE_PROOF_MISSING'}
  return $read
 }finally{$proc.Dispose()}
}

function Sign-Device([string]$message,[object]$identity){$rsa=Open-CspKey ([string]$identity.key_container);try{return [Convert]::ToBase64String($rsa.SignData([Text.Encoding]::UTF8.GetBytes($message),[Security.Cryptography.CryptoConfig]::MapNameToOID('SHA256')))}finally{$rsa.Dispose()}}

function Request([string]$path,[object]$payload,[object]$identity){
 $now=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds();$nonce=[guid]::NewGuid().ToString('N')
 $payloadJson=ConvertTo-Json -InputObject $payload -Depth 8 -Compress
 $hash=Digest ([Text.Encoding]::UTF8.GetBytes($payloadJson))
 $message="UEA-EXEC-AUTH1`n$path`n$($identity.device_id)`n$now`n$nonce`n$hash`n"
 $auth=[ordered]@{device_id=$identity.device_id;issued_ms=$now;nonce=$nonce;payload=$payload;payload_sha256=$hash;signature_b64=(Sign-Device $message $identity)}
 $bytes=[Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $auth -Depth 10 -Compress))
 if($bytes.Length -gt 26000){throw 'TRANSPORT_BODY_TOO_LARGE'}
 [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
 $uri=$CLOUD+$path;$req=[Net.HttpWebRequest][Net.WebRequest]::Create($uri)
 $req.Method='POST';$req.ContentType='application/json';$req.AllowAutoRedirect=$false;$req.Timeout=16000;$req.ReadWriteTimeout=16000;$req.KeepAlive=$false;$req.ContentLength=$bytes.Length
 try{$stream=$req.GetRequestStream();try{$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()};$resp=[Net.HttpWebResponse]$req.GetResponse();try{if([int]$resp.StatusCode -ne 200){throw 'CLOUD_POST_DENIED'};$sr=New-Object IO.StreamReader($resp.GetResponseStream());try{$json=$sr.ReadToEnd()}finally{$sr.Dispose()};if($json.Length -gt 12000){throw 'CLOUD_RESPONSE_TOO_LARGE'};return ($json|ConvertFrom-Json)}finally{$resp.Dispose()}}catch [Net.WebException]{throw 'CLOUD_NETWORK_OR_AUTH_UNAVAILABLE'}
}

function Encrypt-Artifact([byte[]]$plain,[string]$cert,[string]$deviceId,[string]$jobId,[object]$identity,[string]$packageId,[string]$packageSha){
 if($plain.Length -gt 32768){throw 'ARTIFACT_LIMIT'}
 $plainSha=Digest $plain
 $cms=Protect-CmsMessage -To $cert -Content ([Convert]::ToBase64String($plain)) -ErrorAction Stop
 if(-not($cms -is [string]) -or $cms -notmatch 'BEGIN CMS'){throw 'CMS_ENCRYPTION_FAILED'}
 $cipher=[Text.Encoding]::ASCII.GetBytes($cms)
 if($cipher.Length -gt 196608){throw 'ENCRYPTED_ARTIFACT_LIMIT'}
 $cmsSha=Digest $cipher
 $sigMsg="UEA-EXEC-ART1`n$deviceId`n$jobId`n$plainSha`n$cmsSha`n$($plain.Length)`n$packageId`n$packageSha`n"
 $chunks=[int][Math]::Ceiling($cipher.Length/12288.0)
 if($chunks -lt 1 -or $chunks -gt 16){throw 'ARTIFACT_CHUNK_LIMIT'}
 $manifest=[ordered]@{schema=1;algorithm='CMS_ENVELOPED_RSA';package_id=$packageId;package_sha256=$packageSha;chunk_count=$chunks;plaintext_length=$plain.Length;plaintext_sha256=$plainSha;ciphertext_length=$cipher.Length;cms_sha256=$cmsSha;device_signature_b64=(Sign-Device $sigMsg $identity)}
 return @{Data=$cipher;Manifest=$manifest}
}

function Run-Job([object]$claim,[object]$ctrl){
 $id=[string]$claim.job_id;$token=[string]$claim.lease_token
 if($id -notmatch '^ex_[a-f0-9]{32}$' -or $token -notmatch '^[a-f0-9]{32}$'){throw 'JOB_SHAPE_INVALID'}
 if($claim.package_id -cne $ctrl.Allowed.package_id -or $claim.package_sha256 -cne $ctrl.Allowed.package_sha256){throw 'LOCAL_OWNER_APPROVAL_DENIED'}
 if([long]$claim.lease_until_ms -le [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()){throw 'LEASE_EXPIRED'}
 # Persist one-use execution ledger before any effect. Ambiguous crash is never retried automatically.
 $ledger=Join-Path $base 'seen-jobs.txt'
 if(Test-Path -LiteralPath $ledger){if(@(Get-Content -LiteralPath $ledger) -contains $id){throw 'REPLAYED_EXECUTION_ID'}}
 [IO.File]::AppendAllText($ledger,$id+[Environment]::NewLine,(New-Object Text.UTF8Encoding($false)))
 $output=Run-ApprovedPackage $ctrl.Script ([int]$ctrl.Policy.max_runtime_seconds) ([int]$ctrl.Policy.max_output_bytes)
 $plain=[Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject ([ordered]@{schema=1;kind='uea_execution_receipt';job_id=$id;package_id=[string]$claim.package_id;package_sha256=[string]$claim.package_sha256;child_exit_code=0;stdout=$output}) -Depth 5 -Compress))
 $sealed=Encrypt-Artifact $plain $ctrl.Recipient $ctrl.Identity.device_id $id $ctrl.Identity ([string]$claim.package_id) ([string]$claim.package_sha256)
 for($i=0;$i -lt $sealed.Manifest.chunk_count;$i++){
  $offset=$i*12288;$count=[Math]::Min(12288,$sealed.Data.Length-$offset)
  $part=New-Object byte[] $count;[Array]::Copy($sealed.Data,$offset,$part,0,$count)
  $send=[ordered]@{job_id=$id;lease_token=$token;index=$i;content_b64=[Convert]::ToBase64String($part)}
  $ack=Request '/v1/exec/chunk' $send $ctrl.Identity
  if(-not $ack.ok){throw 'CHUNK_NOT_ACKNOWLEDGED'}
 }
 $finish=[ordered]@{job_id=$id;lease_token=$token;status='complete';manifest_json=(ConvertTo-Json -InputObject $sealed.Manifest -Compress);failure_code=''}
 $done=Request '/v1/exec/finish' $finish $ctrl.Identity
 if(-not $done.ok){throw 'FINISH_NOT_ACKNOWLEDGED'}
 return 'UEA_EXEC_JOB_COMPLETE'
}
try {
 if($FromTask){[IO.File]::WriteAllText((Join-Path $base 'task-started.txt'),[DateTime]::UtcNow.ToString('o'))}
 $ctrl=Verify-LocalGrant
 if($SelfTest){
  $parseErrors=$null
  [void][Management.Automation.Language.Parser]::ParseFile($ctrl.Script,[ref]$null,[ref]$parseErrors)
  if(@($parseErrors).Count){throw 'SIGNED_PACKAGE_PARSE_FAILURE'}
  $probe=Protect-CmsMessage -To $ctrl.Recipient -Content 'UEA_EXEC_CMS_SELFTEST' -ErrorAction Stop
  if($probe -notmatch 'BEGIN CMS'){throw 'ENCRYPTION_SELFTEST_FAILED'}
  $localProof=Run-ApprovedPackage $ctrl.Script ([int]$ctrl.Policy.max_runtime_seconds) ([int]$ctrl.Policy.max_output_bytes)
  if($localProof -notmatch 'UEA_SIGNED_REMOTE_EXECUTION_PROOF'){throw 'OFFLINE_CHILD_PROOF_MISSING'}
  Write-Output 'UEA_EXEC_SELFTEST_OK';return
 }
 $claim=Request '/v1/exec/claim' ([ordered]@{}) $ctrl.Identity
 if($claim.state -eq 'empty'){Write-Host 'UEA_EXEC_QUEUE_EMPTY';return}
 if($claim.state -cne 'leased'){throw 'EXEC_CLOUD_STATE_INVALID'}
 try{Write-Host (Run-Job $claim $ctrl)}catch{
  try{$failure=[ordered]@{job_id=$claim.job_id;lease_token=$claim.lease_token;status='denied';manifest_json='';failure_code='LOCAL_OWNER_GATE_OR_EXECUTION_DENIED'};$null=Request '/v1/exec/finish' $failure $ctrl.Identity}catch{}
  throw
 }
}catch{
 $errorCode=$_.Exception.Message
 if($errorCode -cnotmatch '^[A-Z0-9_]{4,80}$'){$errorCode='SAFE_LOCAL_ERROR'}
 Write-Host ('UEA_EXEC_STATUS='+$errorCode)
 if($SelfTest){throw}
}