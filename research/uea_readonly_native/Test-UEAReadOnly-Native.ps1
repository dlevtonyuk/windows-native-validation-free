# Native Windows Server 2025 / Windows PowerShell 5.1 synthetic tests only.
# This test never contacts the UEA cloud, reads real business data, or changes real tasks.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'Run-UEAReadOnly-SYNTHETIC.ps1') -LibraryOnly
$fixture=Join-Path $env:TEMP ('UEA-synthetic-'+[guid]::NewGuid().ToString('N'))
$keyName='UEA-DeviceIdentity-'+[guid]::NewGuid().ToString('N')
$rsa=$null;$passes=0
function Expect([bool]$b,[string]$name){if(-not $b){throw ('FAILED_'+$name)};$script:passes++}
function Deny([scriptblock]$call,[string]$name){$deny=$false;try{& $call|Out-Null}catch{$deny=$true};Expect $deny $name}
try {
 [IO.Directory]::CreateDirectory($fixture)|Out-Null
 [IO.File]::WriteAllText((Join-Path $fixture 'sample.py'),'print("hello")',[Text.Encoding]::UTF8)
 [IO.File]::WriteAllText((Join-Path $fixture 'credentials.txt'),'api_key="SENSITIVE_VERY_LONG_STRING_123456"',[Text.Encoding]::UTF8)
 [IO.File]::WriteAllText((Join-Path $fixture 'drop.exe'),'binary',[Text.Encoding]::UTF8)
 [IO.Directory]::CreateDirectory((Join-Path $fixture 'private'))|Out-Null
 Expect ((Assert-SafePath $fixture '.' 'inventory') -eq $fixture) 'ROOT_INVENTORY'
 Expect ((Assert-SafePath $fixture 'sample.py' 'read_file') -eq (Join-Path $fixture 'sample.py')) 'SOURCE_FILE'
 Deny {Assert-SafePath $fixture '../secret' 'read_file'} 'TRAVERSAL'
 Deny {Assert-SafePath $fixture 'C:\secrets' 'read_file'} 'ABSOLUTE'
 Deny {Assert-SafePath $fixture 'private' 'inventory'} 'PRIVATE_DIRECTORY'
 Deny {Assert-SafePath $fixture 'drop.exe' 'read_file'} 'EXE_EXTENSION'
 Deny {Assert-SafePath $fixture 'nope.ps1' 'read_file'} 'MISSING_FILE'
 Deny {Read-Source $fixture 'credentials.txt' 32768} 'INLINE_KEY'
 $read=Read-Source $fixture 'sample.py' 32768
 Expect (([Text.Encoding]::UTF8.GetString([byte[]]$read)) -eq 'print("hello")') 'READ_SOURCE'
 $inventory=Inventory $fixture '.'
 $listing=[Text.Encoding]::UTF8.GetString([byte[]]$inventory)|ConvertFrom-Json
 Expect ($listing.operation -eq 'inventory') 'INVENTORY'
 $csp=[Security.Cryptography.CspParameters]::new(24,'Microsoft Enhanced RSA and AES Cryptographic Provider',$keyName)
 $csp.Flags=[Security.Cryptography.CspProviderFlags]::UseNonExportableKey
 $rsa=[Security.Cryptography.RSACryptoServiceProvider]::new(2048,$csp);$rsa.PersistKeyInCsp=$true
 $id=[pscustomobject]@{key_container=$keyName;device_id='dev_'+('a'*32)}
 $msg='UEA-SYNTHETIC-SIGNATURE';$sig=Sign-Device $msg $id
 Expect (([Convert]::FromBase64String($sig)).Length -eq 256) 'DEVICE_SIGNATURE'
 $blob=Encrypt-Artifact ([Text.Encoding]::UTF8.GetBytes('test artifact')) (Join-Path $PSScriptRoot 'recipient.cer') $id.device_id ('ro_'+('b'*32)) $id
 Expect ($blob.Manifest.algorithm -eq 'CMS_ENVELOPED_RSA') 'CMS_ALGORITHM'
 Expect ($blob.Manifest.chunk_count -ge 1) 'CMS_CHUNKS'
 Expect (([Text.Encoding]::ASCII.GetString($blob.Data)) -match 'BEGIN CMS') 'CMS_PEM'
 Write-Host ('UEA_NATIVE_WINDOWS_READONLY_TESTS_PASSED='+$passes)
}finally{
 if($rsa){$rsa.PersistKeyInCsp=$false;$rsa.Clear();$rsa.Dispose()}
 if(Test-Path -LiteralPath $fixture){Remove-Item -LiteralPath $fixture -Recurse -Force}
}