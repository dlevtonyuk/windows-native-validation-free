#requires -Version 5.1
# UEA v0.4 generic, owner-signed, read-only file inspection. Never executes jobs or scripts.
[CmdletBinding()]
param([switch]$FromTask,[switch]$SelfTest,[switch]$LibraryOnly)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$base=Split-Path -Parent $MyInvocation.MyCommand.Path
$hbBase=Join-Path $env:LOCALAPPDATA 'ChatGPT\UEA-DeviceAgent'
$CLOUD='https://example.invalid'
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
function Assert-Policy {
 $cfgPath=Join-Path $base 'owner-grant.json'
 if(-not(Test-Path -LiteralPath $cfgPath -PathType Leaf)){throw 'OWNER_GRANT_MISSING'}
 $grant=Get-Content -LiteralPath $cfgPath -Raw | ConvertFrom-Json
 if($grant.schema -ne 1 -or [string]$grant.policy_json -eq '' -or [string]$grant.signature_b64 -eq ''){throw 'OWNER_GRANT_SHAPE'}
 $policy=$grant.policy_json|ConvertFrom-Json
 if($policy.version -ne 1 -or $policy.revision -lt 1 -or $policy.device_id -notmatch '^dev_[0-9a-f]{32}$' -or $policy.max_file_bytes -ne 32768){throw 'OWNER_POLICY_INVALID'}
 if([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() -ge [long]$policy.expires_ms){throw 'OWNER_POLICY_EXPIRED'}
 if($policy.root_id -notmatch '^[a-z][a-z0-9_]{2,40}$' -or $policy.root_path -notmatch '^[A-Za-z]:\\' -or $policy.root_path.Length -gt 200){throw 'OWNER_ROOT_INVALID'}
 if(@($policy.operations).Count -ne 2 -or @($policy.operations) -notcontains 'inventory' -or @($policy.operations) -notcontains 'read_file'){throw 'OWNER_OPERATIONS_INVALID'}
 $cert=Join-Path $base 'recipient.cer';if(-not(Test-Path -LiteralPath $cert -PathType Leaf)){throw 'RECIPIENT_MISSING'}
 if((Get-FileHash -LiteralPath $cert -Algorithm SHA256).Hash.ToLowerInvariant() -cne $policy.recipient_cert_sha256){throw 'RECIPIENT_CHANGED'}
 $identity=Get-Content -LiteralPath (Join-Path $hbBase 'device-public.json') -Raw|ConvertFrom-Json
 if($identity.device_id -cne $policy.device_id){throw 'DEVICE_ID_MISMATCH'}
 $rsa=PublicKey $grant.owner_public_jwk
 try {$sig=[Convert]::FromBase64String([string]$grant.signature_b64);if($sig.Length -ne 256 -or -not $rsa.VerifyData([Text.Encoding]::UTF8.GetBytes([string]$grant.policy_json),[Security.Cryptography.CryptoConfig]::MapNameToOID('SHA256'),$sig)){throw 'OWNER_SIGNATURE_INVALID'}}finally{$rsa.Dispose()}
 if(Test-Path -LiteralPath (Join-Path $base 'local-stop.flag') -PathType Leaf){throw 'LOCAL_STOP_REQUESTED'}
 return @{Policy=$policy;Identity=$identity;Certificate=$cert}
}
function Assert-SafePath([string]$root,[string]$relative,[string]$operation){
 if($relative -ne '.' -and ($relative.Length -lt 1 -or $relative.Length -gt 200 -or $relative -cnotmatch '^[A-Za-z0-9_.\\/-]+$' -or $relative.Contains('..') -or $relative.StartsWith('/') -or $relative.StartsWith('\\') -or $relative.Contains(':'))){throw 'RELATIVE_PATH_DENIED'}
 $root=[IO.Path]::GetFullPath($root).TrimEnd('\');if(-not(Test-Path -LiteralPath $root -PathType Container)){throw 'AUTHORIZED_ROOT_UNAVAILABLE'}
 $segments=if($relative -eq '.'){@()}else{@($relative -split '[\\/]')}
 $bad='(?i)^(private|secrets?|credentials?|keys?|backup|backups|\.git|node_modules|\.venv|venv|logs?|cache|\.env|data)$'
 $at=$root
 foreach($s in $segments){if($s -eq '' -or $s -eq '.' -or $s -match $bad){throw 'PATH_COMPONENT_DENIED'};$at=Join-Path $at $s}
 $candidate=[IO.Path]::GetFullPath($at)
 if($candidate -cne $root -and -not $candidate.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'ROOT_ESCAPE_DENIED'}
 # Reject reparse points anywhere in the walked path, including root and file.
 $walk=$root
 if((Get-Item -LiteralPath $walk -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'REPARSE_POINT_DENIED'}
 foreach($s in $segments){$walk=Join-Path $walk $s;$item=Get-Item -LiteralPath $walk -Force -ErrorAction Stop;if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'REPARSE_POINT_DENIED'}}
 if($operation -eq 'inventory'){
   if(-not(Test-Path -LiteralPath $candidate -PathType Container)){throw 'NOT_A_DIRECTORY'}
 }elseif($operation -eq 'read_file'){
   if(-not(Test-Path -LiteralPath $candidate -PathType Leaf)){throw 'NOT_A_FILE'}
   $ext=[IO.Path]::GetExtension($candidate).ToLowerInvariant()
   if($ext -notin @('.ps1','.psm1','.py','.md','.txt','.json','.yaml','.yml','.js','.mjs','.ts','.toml','.sql')){throw 'EXTENSION_DENIED'}
 }else{throw 'OPERATION_DENIED'}
 return $candidate
}
function Inventory([string]$root,[string]$relative){
 $folder=Assert-SafePath $root $relative 'inventory'
 $items=@(Get-ChildItem -LiteralPath $folder -Force -ErrorAction Stop | Sort-Object Name | Select-Object -First 100)
 $out=New-Object System.Collections.ArrayList
 foreach($x in $items){
   try {
     if($x.Name -notmatch '^[A-Za-z0-9_.-]{1,90}$'){continue}
     $rel=if($relative -eq '.'){$x.Name}else{$relative.TrimEnd('/','\')+'/'+$x.Name}
     if($x.PSIsContainer){$null=Assert-SafePath $root $rel 'inventory';$null=$out.Add([ordered]@{name=$x.Name;kind='directory'})}
     else{$null=Assert-SafePath $root $rel 'read_file';if($x.Length -le 32768){$null=$out.Add([ordered]@{name=$x.Name;kind='file';bytes=[long]$x.Length})}}
   }catch{continue}
 }
 return [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject ([ordered]@{schema=1;operation='inventory';path=$relative;entries=@($out.ToArray());truncated=(@($items).Count -ge 100)}) -Depth 6 -Compress))
}
function Read-Source([string]$root,[string]$relative,[int]$max){
 $p=Assert-SafePath $root $relative 'read_file';$item=Get-Item -LiteralPath $p -Force
 if($item.Length -gt $max){throw 'FILE_TOO_LARGE'}
 $bytes=[IO.File]::ReadAllBytes($p);$after=Get-Item -LiteralPath $p -Force
 if($bytes.Length -gt $max -or $after.Length -ne $item.Length -or $after.LastWriteTimeUtc -ne $item.LastWriteTimeUtc){throw 'FILE_CHANGED_DURING_READ'}
 # UTF-8 source files only; disallow obvious embedded literal credential values.
 $utf8=New-Object Text.UTF8Encoding($false,$true);try{$content=$utf8.GetString($bytes)}catch{throw 'NON_UTF8_SOURCE_DENIED'}
 if($content -match '(?im)^\s*[^\r\n#]{0,64}(?:access[_-]?token|refresh[_-]?token|client[_-]?secret|api[_-]?key|password)\s*[:=]\s*["'']?[^\s"'']{12,}' -or $content -match '-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'){throw 'CREDENTIAL_PATTERN_DENIED'}
 return $bytes
}
function Sign-Device([string]$message,[object]$identity){$rsa=Open-CspKey ([string]$identity.key_container);try{return [Convert]::ToBase64String($rsa.SignData([Text.Encoding]::UTF8.GetBytes($message),[Security.Cryptography.CryptoConfig]::MapNameToOID('SHA256')))}finally{$rsa.Dispose()}}
function Request([string]$path,[object]$payload,[object]$identity){
 $now=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds();$nonce=[guid]::NewGuid().ToString('N')
 $payloadJson=ConvertTo-Json -InputObject $payload -Depth 8 -Compress
 $hash=Digest ([Text.Encoding]::UTF8.GetBytes($payloadJson))
 $message="UEA-RO-AUTH1`n$path`n$($identity.device_id)`n$now`n$nonce`n$hash`n"
 $auth=[ordered]@{device_id=$identity.device_id;issued_ms=$now;nonce=$nonce;payload=$payload;payload_sha256=$hash;signature_b64=(Sign-Device $message $identity)}
 $bytes=[Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $auth -Depth 10 -Compress))
 if($bytes.Length -gt 26000){throw 'TRANSPORT_BODY_TOO_LARGE'}
 [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
 $uri=$CLOUD+$path;$req=[Net.HttpWebRequest][Net.WebRequest]::Create($uri)
 $req.Method='POST';$req.ContentType='application/json';$req.AllowAutoRedirect=$false;$req.Timeout=16000;$req.ReadWriteTimeout=16000;$req.KeepAlive=$false;$req.ContentLength=$bytes.Length
 try{$stream=$req.GetRequestStream();try{$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()};$resp=[Net.HttpWebResponse]$req.GetResponse();try{if([int]$resp.StatusCode -ne 200){throw 'CLOUD_POST_DENIED'};$sr=New-Object IO.StreamReader($resp.GetResponseStream());try{$json=$sr.ReadToEnd()}finally{$sr.Dispose()};if($json.Length -gt 12000){throw 'CLOUD_RESPONSE_TOO_LARGE'};return ($json|ConvertFrom-Json)}finally{$resp.Dispose()}}catch [Net.WebException]{throw 'CLOUD_NETWORK_OR_AUTH_UNAVAILABLE'}
}
function Encrypt-Artifact([byte[]]$plain,[string]$cert,[string]$deviceId,[string]$jobId,[object]$identity){
 if($plain.Length -gt 32768){throw 'ARTIFACT_LIMIT'}
 $plainSha=Digest $plain
 $cms=Protect-CmsMessage -To $cert -Content ([Convert]::ToBase64String($plain)) -ErrorAction Stop
 if(-not($cms -is [string]) -or $cms -notmatch 'BEGIN CMS'){throw 'CMS_ENCRYPTION_FAILED'}
 $cipher=[Text.Encoding]::ASCII.GetBytes($cms)
 if($cipher.Length -gt 196608){throw 'ENCRYPTED_ARTIFACT_LIMIT'}
 $cmsSha=Digest $cipher
 $sigMsg="UEA-READ-ART1`n$deviceId`n$jobId`n$plainSha`n$cmsSha`n$($plain.Length)`n"
 $chunks=[int][Math]::Ceiling($cipher.Length/12288.0)
 if($chunks -lt 1 -or $chunks -gt 16){throw 'ARTIFACT_CHUNK_LIMIT'}
 $manifest=[ordered]@{schema=1;algorithm='CMS_ENVELOPED_RSA';chunk_count=$chunks;plaintext_length=$plain.Length;plaintext_sha256=$plainSha;ciphertext_length=$cipher.Length;cms_sha256=$cmsSha;device_signature_b64=(Sign-Device $sigMsg $identity)}
 return @{Data=$cipher;Manifest=$manifest}
}
function Run-Job([object]$claim,[object]$controls){
 $id=[string]$claim.job_id;$token=[string]$claim.lease_token
 if($id -notmatch '^ro_[a-f0-9]{32}$' -or $token -notmatch '^[a-f0-9]{32}$'){throw 'CLOUD_JOB_SHAPE'}
 $policy=$controls.Policy;$identity=$controls.Identity
 if($claim.root_id -cne $policy.root_id -or $claim.recipient_cert_sha256 -cne $policy.recipient_cert_sha256 -or @($policy.operations) -notcontains $claim.operation){throw 'OWNER_SCOPE_DENIED'}
 if($claim.operation -notin @('inventory','read_file')){throw 'OPERATION_DENIED'}
 if([long]$claim.lease_until_ms -lt [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()){throw 'CLOUD_LEASE_EXPIRED'}
 # One-shot local audit fence before attempting reading.
 $ledger=Join-Path $base 'seen-jobs.txt'
 if(Test-Path -LiteralPath $ledger){if(@(Get-Content -LiteralPath $ledger) -contains $id){throw 'DUPLICATE_JOB_ID'}}
 [IO.File]::AppendAllText($ledger,$id+[Environment]::NewLine,(New-Object Text.UTF8Encoding($false)))
 $source=if($claim.operation -eq 'inventory'){Inventory ([string]$policy.root_path) ([string]$claim.rel_path)}else{Read-Source ([string]$policy.root_path) ([string]$claim.rel_path) ([int]$policy.max_file_bytes)}
 $sealed=Encrypt-Artifact $source $controls.Certificate $identity.device_id $id $identity
 for($i=0;$i -lt $sealed.Manifest.chunk_count;$i++){
   $start=$i*12288;$len=[Math]::Min(12288,$sealed.Data.Length-$start);$slice=New-Object byte[] $len;[Array]::Copy($sealed.Data,$start,$slice,0,$len)
   $payload=[ordered]@{job_id=$id;lease_token=$token;index=$i;content_b64=[Convert]::ToBase64String($slice)}
   $response=Request '/v1/agent/chunk' $payload $identity
   if(-not $response.ok){throw 'CHUNK_NOT_ACCEPTED'}
 }
 $final=[ordered]@{job_id=$id;lease_token=$token;status='complete';manifest_json=(ConvertTo-Json -InputObject $sealed.Manifest -Compress);failure_code=''}
 $answer=Request '/v1/agent/finish' $final $identity;if(-not $answer.ok){throw 'COMPLETION_NOT_ACCEPTED'}
 return 'JOB_COMPLETED'
}
if($LibraryOnly){return}
try {
 if($FromTask){[IO.File]::WriteAllText((Join-Path $base 'task-started.txt'),[DateTime]::UtcNow.ToString('o'))}
 $controls=Assert-Policy
 if($SelfTest){
   $null=Assert-SafePath ([string]$controls.Policy.root_path) '.' 'inventory'
   foreach($bad in @('../private','.\\..\\secret','C:\secret','\\server\share')){
     try{$null=Assert-SafePath ([string]$controls.Policy.root_path) $bad 'read_file';throw 'SELFTEST_TRAVERSAL_ALLOWED'}catch{if($_.Exception.Message -eq 'SELFTEST_TRAVERSAL_ALLOWED'){throw}}
   }
   $probe=Protect-CmsMessage -To $controls.Certificate -Content 'UEA_READONLY_CMS_SELFTEST'
   if($probe -notmatch 'BEGIN CMS'){throw 'CMS_SELFTEST_FAILED'}
   Write-Output 'UEA_RO_SELFTEST_PASSED';return
 }
 $claim=Request '/v1/agent/claim' ([ordered]@{}) $controls.Identity
 if($claim.state -eq 'empty'){Write-Host 'UEA_RO_NO_JOBS';return}
 if($claim.state -ne 'leased'){throw 'CLOUD_JOB_STATE_UNEXPECTED'}
 try {Write-Host (Run-Job $claim $controls)}catch{
   $code='LOCAL_SCOPE_OR_EXECUTION_DENIED'
   try{$payload=[ordered]@{job_id=$claim.job_id;lease_token=$claim.lease_token;status='denied';manifest_json='';failure_code=$code};$null=Request '/v1/agent/finish' $payload $controls.Identity}catch{}
   throw
 }
}catch {
 $msg=$_.Exception.Message
 if($msg -notmatch '^[A-Z0-9_]{4,80}$'){$msg='SAFE_LOCAL_FAILURE'}
 Write-Host ('UEA_RO_STATUS='+$msg)
 if($SelfTest){throw}
}