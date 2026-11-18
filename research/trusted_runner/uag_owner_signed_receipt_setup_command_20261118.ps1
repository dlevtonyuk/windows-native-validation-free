# Owner-private UAG signed-receipt setup, November 18, 2026.
# Distributed by immutable GitHub blob with Git-object hash verification. No manual download required.
# Run locally via authenticated gh CLI. Changes only two specified paths in
# the owner's private repo; does not expose credentials or touch existing apps.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = [string]$env:UAG_OWNER_PRIVATE_REPO
if ($repo -cnotmatch '^dlevtonyuk/[A-Za-z0-9_.-]+$') { throw 'OWNER_REPO_NOT_SET_OR_INVALID' }
$workflowPath = '.github/workflows/uag-owner-trusted-runner.yml'
$reporterPath = 'owner_signed_receipt.mjs'
$existingExpectedSha = '02f16ead77bd7a0965ed485191e8bdba150c9584'
$newExpectedSha = '5f78b77d8ec2c45e1718a9e9220b2b0b511575ee'
$reporterExpectedSha = '018c204c146eb253015811a4fdcca2c82fe8ebf3'
$sourceCommit = 'cbc7bf15a008b2866d3edd28d7abc1f87c09e738'
$endpoint = 'https://uag-owner-signed-receipts.dlevtonyuk.workers.dev/health'
$script:branch = ''

function RequireGh([string]$label) { if ($LASTEXITCODE -ne 0) { throw "GH_OPERATION_FAILED: $label" } }
function BlobSha([byte[]]$bytes) {
  $prefix=[Text.Encoding]::UTF8.GetBytes("blob $($bytes.Length)`0")
  $inputBytes=New-Object byte[] ($prefix.Length + $bytes.Length)
  [Array]::Copy($prefix,0,$inputBytes,0,$prefix.Length)
  [Array]::Copy($bytes,0,$inputBytes,$prefix.Length,$bytes.Length)
  $hash=[Security.Cryptography.SHA1]::Create()
  try { return ([BitConverter]::ToString($hash.ComputeHash($inputBytes))).Replace('-','').ToLowerInvariant() }
  finally { $hash.Dispose() }
}
function Tree {
  $raw=(& gh api "repos/$repo/git/trees/$($script:branch)?recursive=1" | Out-String)
  RequireGh 'Reading private tree'
  $tree=$raw|ConvertFrom-Json
  if ($tree.truncated) {throw 'PRIVATE_TREE_TRUNCATED'}
  return @($tree.tree)
}
function PathSha([string]$path) {
  $matches=@(Tree | Where-Object { $_.path -ceq $path })
  if ($matches.Count -gt 1) {throw "DUPLICATE_PATH: $path"}
  if ($matches.Count -eq 0) { return '' }
  return [string]$matches[0].sha
}
function CommitExact([string]$path,[byte[]]$bytes,[string]$wanted,[string]$previous='') {
  if ((BlobSha $bytes) -cne $wanted) {throw "LOCAL_HASH_MISMATCH: $path"}
  $old=PathSha $path
  if ($old -ceq $wanted) { Write-Host "VERIFIED_UNCHANGED: $path";return }
  if ($old -and $old -cne $previous) { throw "EXISTING_DIFFERENT_FILE: $path. Refusing overwrite." }
  $payload=@{message='Owner-approved signed UAG telemetry only';branch=$script:branch;content=[Convert]::ToBase64String($bytes)}
  if ($old) {$payload.sha=$old}
  $temp=[IO.Path]::GetTempFileName()
  try {
    [IO.File]::WriteAllText($temp,($payload|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
    $reply=(& gh api -X PUT "repos/$repo/contents/$path" --input $temp | Out-String)
    RequireGh "Committing $path"
    if (($reply|ConvertFrom-Json).content.sha -cne $wanted) {throw "REMOTE_HASH_MISMATCH: $path"}
    Write-Host "COMMITTED_AND_VERIFIED: $path"
  } finally { Remove-Item $temp -Force -ErrorAction SilentlyContinue }
}
function Get-PinnedWorkflow {
  $url="https://raw.githubusercontent.com/dlevtonyuk/windows-native-validation-free/$sourceCommit/research/trusted_runner/owner_private_runner.yml"
  $temp=[IO.Path]::GetTempFileName()
  try {
    Invoke-WebRequest -Uri $url -UseBasicParsing -OutFile $temp | Out-Null
    $bytes=[IO.File]::ReadAllBytes($temp)
    if ((BlobSha $bytes) -cne $existingExpectedSha) {throw 'PINNED_SOURCE_MISMATCH'}
    $text=[Text.Encoding]::UTF8.GetString($bytes)
    return $text
  } finally {Remove-Item $temp -Force -ErrorAction SilentlyContinue}
}
Write-Host '=== UAG OWNER SIGNED RECEIPT — OWNER-ONLY INSTALLATION ==='
if(-not(Get-Command gh -ErrorAction SilentlyContinue)){throw 'GITHUB_CLI_NOT_FOUND'}
$me=(& gh api user --jq '.login' | Out-String).Trim();RequireGh 'Checking identity'
if($me -cne 'dlevtonyuk'){throw 'WRONG_GITHUB_ACCOUNT'}
$metadata=(& gh repo view $repo --json nameWithOwner,visibility,defaultBranchRef | Out-String);RequireGh 'Verifying private repo'
$info=$metadata|ConvertFrom-Json
if($info.nameWithOwner -cne $repo -or $info.visibility -cne 'PRIVATE' -or $info.defaultBranchRef.name -cne 'main'){throw 'PRIVATE_REPO_CONFIGURATION_CHANGED'}
$script:branch='main'
Write-Host 'PRIVATE_REPOSITORY_VERIFIED: owner dlevtonyuk, main, PRIVATE'
# This live GET does not transmit any credential.
try {$h=Invoke-RestMethod -Uri $endpoint -Method Get -TimeoutSec 15 -ErrorAction Stop; if($h.ok -ne $true -or $h.mode -cne 'owner-private-oidc-only'){throw 'UNEXPECTED_HEALTH_RESPONSE'}}
catch { throw 'RECEIVER_HEALTH_FAILED: nothing changed on GitHub. Copy this status to ChatGPT for repair.' }
Write-Host 'CLOUDFLARE_RECEIVER_HEALTH_PASSED'
$original=Get-PinnedWorkflow
$workflowBytes=[Convert]::FromBase64String('IyBPV05FUi1QUklWQVRFIFJFUE8gVEVNUExBVEUgT05MWS4gTk9UIElOU1RBTExFRCBPUiBSVU4gSEVSRS4KIyBPd25lciBtdXN0IGZpcnN0IHJlc3RyaWN0IENoYXRHUFQgR2l0SHViIGFwcCBpbnN0YWxsYXRpb24gdG8gZXhpc3RpbmcgcmVwb3MsCiMgYW5kIGluZGVwZW5kZW50bHkgdmVyaWZ5IHRoaXMgc2VwYXJhdGUgcHJpdmF0ZSByZXBvIGlzIG5vdCBhcHAtYWNjZXNzaWJsZS4KIyBObyBwcm92aWRlciBBUEkgb3IgcHJpdmlsZWdlZCBhY3Rpb24gaXMgcGVyZm9ybWVkIGJ5IHRoaXMgdGVtcGxhdGUuCm5hbWU6IFVBRyBPd25lciBUcnVzdGVkIFJlYWQtT25seSBSdW5uZXIKb246CiAgc2NoZWR1bGU6CiAgICAtIGNyb246ICcxNyAqICogKiAqJwogIHdvcmtmbG93X2Rpc3BhdGNoOgpwZXJtaXNzaW9uczoKICBjb250ZW50czogcmVhZAogIGlkLXRva2VuOiB3cml0ZQpjb25jdXJyZW5jeToKICBncm91cDogdWFnLXRydXN0ZWQtcnVubmVyCiAgY2FuY2VsLWluLXByb2dyZXNzOiBmYWxzZQpqb2JzOgogIGZvdW5kYXRpb24tcmVhZC1vbmx5OgogICAgcnVucy1vbjogdWJ1bnR1LTI0LjA0CiAgICB0aW1lb3V0LW1pbnV0ZXM6IDMKICAgIHN0ZXBzOgogICAgICAtIHVzZXM6IGFjdGlvbnMvY2hlY2tvdXRAdjQKICAgICAgICB3aXRoOgogICAgICAgICAgcGVyc2lzdC1jcmVkZW50aWFsczogZmFsc2UKICAgICAgLSB1c2VzOiBhY3Rpb25zL3NldHVwLW5vZGVAdjQKICAgICAgICB3aXRoOgogICAgICAgICAgbm9kZS12ZXJzaW9uOiAnMjInCiAgICAgIC0gbmFtZTogT3duZXItb25seSBmaXhlZCBEMSBTRUxFQ1QgcHJvYmUKICAgICAgICBpZDogcHJvYmUKICAgICAgICBlbnY6CiAgICAgICAgICBVQUdfQ0ZfQUNDT1VOVF9JRDogJHt7IHZhcnMuVUFHX0NGX0FDQ09VTlRfSUQgfX0KICAgICAgICAgIFVBR19DRl9EMV9EQVRBQkFTRV9JRDogJHt7IHZhcnMuVUFHX0NGX0QxX0RBVEFCQVNFX0lEIH19CiAgICAgICAgICBVQUdfQ0ZfRDFfUkVBRF9UT0tFTjogJHt7IHNlY3JldHMuVUFHX0NGX0QxX1JFQURfVE9LRU4gfX0KICAgICAgICBydW46IG5vZGUgLi9wcml2YXRlX3J1bm5lcl9tYWluLm1qcwogICAgICAtIG5hbWU6IFN1Ym1pdCBzaWduZWQsIG1ldGFkYXRhLW9ubHkgZXhlY3V0aW9uIHJlY2VpcHQKICAgICAgICBpZjogJHt7IGFsd2F5cygpIH19CiAgICAgICAgZW52OgogICAgICAgICAgVUFHX1BST0JFX1NUQVRVUzogJHt7IHN0ZXBzLnByb2JlLm91dGNvbWUgfX0KICAgICAgICBydW46IG5vZGUgLi9vd25lcl9zaWduZWRfcmVjZWlwdC5tanMK')
if((BlobSha $workflowBytes) -cne $newExpectedSha){throw 'UPDATED_WORKFLOW_HASH_MISMATCH'}
$reporterBytes=[Convert]::FromBase64String('Ly8gT3duZXItcHJpdmF0ZSBHaXRIdWIgQWN0aW9ucyByZXBvcnRlciwgaW5zdGFsbGVkIG9ubHkgaW5zaWRlIHRoZSBvd25lcidzCi8vIGV4Y2x1ZGVkIHByaXZhdGUgcmVwby4gRG9lcyBub3QgcmVhZCBvciB0cmFuc21pdCB0aGUgQ2xvdWRmbGFyZSBEMSBzZWNyZXQuCmNvbnN0IFVSTD0naHR0cHM6Ly91YWctb3duZXItc2lnbmVkLXJlY2VpcHRzLmRsZXZ0b255dWsud29ya2Vycy5kZXYvdjEvcmVjZWlwdCc7CmNvbnN0IEFVRD0ndWFnLW93bmVyLXJlY2VpcHRzLXYxJzsKYXN5bmMgZnVuY3Rpb24gbWFpbigpewogIGNvbnN0IHN0YXR1cz1wcm9jZXNzLmVudi5VQUdfUFJPQkVfU1RBVFVTOwogIGlmKCFbJ3N1Y2Nlc3MnLCdmYWlsdXJlJ10uaW5jbHVkZXMoc3RhdHVzKSl0aHJvdyBFcnJvcignUFJPQkVfU1RBVFVTX1VOQVZBSUxBQkxFJyk7CiAgY29uc3QgcmVxdWVzdFVybD1wcm9jZXNzLmVudi5BQ1RJT05TX0lEX1RPS0VOX1JFUVVFU1RfVVJMOwogIGNvbnN0IHJlcXVlc3RUb2tlbj1wcm9jZXNzLmVudi5BQ1RJT05TX0lEX1RPS0VOX1JFUVVFU1RfVE9LRU47CiAgaWYoIXJlcXVlc3RVcmx8fCFyZXF1ZXN0VG9rZW4pdGhyb3cgRXJyb3IoJ0dJVEhVQl9PSURDX05PVF9FTkFCTEVEJyk7CiAgY29uc3Qgb2lkY1VybD1uZXcgVVJMKHJlcXVlc3RVcmwpOwogIGlmKG9pZGNVcmwucHJvdG9jb2whPT0naHR0cHM6Jyl0aHJvdyBFcnJvcignVU5TQUZFX09JRENfUkVRVUVTVF9VUkwnKTsKICBvaWRjVXJsLnNlYXJjaFBhcmFtcy5zZXQoJ2F1ZGllbmNlJyxBVUQpOwogIGNvbnN0IG9pZGM9YXdhaXQgZmV0Y2gob2lkY1VybCx7aGVhZGVyczp7QXV0aG9yaXphdGlvbjonYmVhcmVyICcrcmVxdWVzdFRva2VufSxyZWRpcmVjdDonZXJyb3InLHNpZ25hbDpBYm9ydFNpZ25hbC50aW1lb3V0KDEwMDAwKX0pOwogIGlmKCFvaWRjLm9rKXRocm93IEVycm9yKCdPSURDX1JFUVVFU1RfRkFJTEVEJyk7CiAgY29uc3QgcmVzcG9uc2U9YXdhaXQgb2lkYy5qc29uKCk7CiAgY29uc3Qgand0PXJlc3BvbnNlLnZhbHVlOwogIGlmKHR5cGVvZiBqd3QhPT0nc3RyaW5nJ3x8and0Lmxlbmd0aDw2NHx8and0Lmxlbmd0aD4xMjAwMCl0aHJvdyBFcnJvcignT0lEQ19SRVNQT05TRV9JTlZBTElEJyk7CiAgY29uc3QgcmVzdWx0PWF3YWl0IGZldGNoKFVSTCx7bWV0aG9kOidQT1NUJyxyZWRpcmVjdDonZXJyb3InLGhlYWRlcnM6e0F1dGhvcml6YXRpb246J0JlYXJlciAnK2p3dCwnQ29udGVudC1UeXBlJzonYXBwbGljYXRpb24vanNvbid9LGJvZHk6SlNPTi5zdHJpbmdpZnkoe3Byb2JlX3N0YXR1czpzdGF0dXN9KSxzaWduYWw6QWJvcnRTaWduYWwudGltZW91dCgxNTAwMCl9KTsKICBpZighcmVzdWx0Lm9rKXRocm93IEVycm9yKCdSRUNFSVBUX1JFSkVDVEVEX0hUVFBfJytyZXN1bHQuc3RhdHVzKTsKICBjb25zdCBib2R5PWF3YWl0IHJlc3VsdC5qc29uKCk7CiAgaWYoYm9keS5vayE9PXRydWUpdGhyb3cgRXJyb3IoJ1JFQ0VJUFRfTk9UX0FDS05PV0xFREdFRCcpOwogIHByb2Nlc3Muc3Rkb3V0LndyaXRlKCdTSUdORURfUkVDRUlQVF9BQ0tOT1dMRURHRUQ6JytzdGF0dXMrJ1xuJyk7Cn0KbWFpbigpLmNhdGNoKGU9Pntjb25zdCBhbGxvd2VkPS9eKFBST0JFX1NUQVRVU19VTkFWQUlMQUJMRXxHSVRIVUJfT0lEQ19OT1RfRU5BQkxFRHxVTlNBRkVfT0lEQ19SRVFVRVNUX1VSTHxPSURDX1JFUVVFU1RfRkFJTEVEfE9JRENfUkVTUE9OU0VfSU5WQUxJRHxSRUNFSVBUX1JFSkVDVEVEX0hUVFBfWzAtOV17M318UkVDRUlQVF9OT1RfQUNLTk9XTEVER0VEKSQvO2NvbnN0IG1zZz1hbGxvd2VkLnRlc3QoZT8ubWVzc2FnZXx8JycpP2UubWVzc2FnZTonVU5DTEFTU0lGSUVEJztwcm9jZXNzLnN0ZGVyci53cml0ZSgnU0lHTkVEX1JFQ0VJUFRfRVJST1I6Jyttc2crJ1xuJyk7cHJvY2Vzcy5leGl0Q29kZT0xO30pOwo=')
if((BlobSha $reporterBytes) -cne $reporterExpectedSha){throw 'REPORTER_HASH_MISMATCH'}
$workflowCurrent=PathSha $workflowPath
if($workflowCurrent -cne $existingExpectedSha -and $workflowCurrent -cne $newExpectedSha){throw "PROTECTED_WORKFLOW_DIFFERENT: $workflowCurrent. Refusing edit."}
$reporterCurrent=PathSha $reporterPath
if($reporterCurrent -and $reporterCurrent -cne $reporterExpectedSha){throw 'EXISTING_REPORTER_DIFFERENT. Refusing edit.'}
Write-Host 'SOURCE_AND_BOUNDARY_PREFLIGHT_PASSED'
CommitExact $reporterPath $reporterBytes $reporterExpectedSha
CommitExact $workflowPath $workflowBytes $newExpectedSha $existingExpectedSha
Write-Host 'SIGNED_RECEIPT_REPORTER_INSTALLED. Original foundation query script unchanged.'
# One safe manual verification of the published receipt. Existing hourly cron stays at :17.
$started=[DateTime]::UtcNow.AddSeconds(-5)
& gh workflow run uag-owner-trusted-runner.yml -R $repo --ref main | Out-Null
RequireGh 'Dispatching signed receipt test'
Write-Host 'REPORTER_MANUAL_TEST_DISPATCHED'
$runId=''
for($n=0;$n -lt 18;$n++) {
  Start-Sleep -Seconds 4
  $runs=(& gh run list -R $repo --workflow uag-owner-trusted-runner.yml --limit 10 --json databaseId,event,createdAt,status,conclusion | Out-String)
  RequireGh 'Finding latest run'
  $runEntries=ConvertFrom-Json -InputObject $runs
  $matchItems=New-Object System.Collections.ArrayList
  foreach($entry in $runEntries) {
    if($entry.event -cne 'workflow_dispatch') { continue }
    try { $createdUtc=[DateTimeOffset]::Parse([string]$entry.createdAt).UtcDateTime } catch { continue }
    if($createdUtc -ge $started) { [void]$matchItems.Add($entry) }
  }
  $matches=@($matchItems | Sort-Object createdAt -Descending)
  if($matches.Count -gt 0){$runId=[string]$matches[0].databaseId;break}
}
if(-not $runId){Write-Host 'REPORTER_RUN_DISCOVERY_PENDING: inspect private GitHub Actions; no other changes required.';exit 2}
for($n=0;$n -lt 22;$n++){
  $view=(& gh run view $runId -R $repo --json status,conclusion | Out-String)
  RequireGh 'Reading reporter test'
  $state=$view|ConvertFrom-Json
  if($state.status -ceq 'completed'){
    if($state.conclusion -cne 'success'){Write-Host "REPORTER_MANUAL_TEST_FAILED: run $runId ; check only sanitized error code in private Actions.";exit 3}
    Write-Host "REPORTER_MANUAL_TEST_PASSED: run $runId"
    Write-Host 'REPORTER_OWNER_SETUP_COMPLETE: SEND THIS STATUS TO CHATGPT; it can verify actual receipt independently in Cloudflare.'
    exit 0
  }
  Start-Sleep -Seconds 5
}
Write-Host "REPORTER_MANUAL_TEST_PENDING: run $runId; do not reinstall or change permissions."
exit 4