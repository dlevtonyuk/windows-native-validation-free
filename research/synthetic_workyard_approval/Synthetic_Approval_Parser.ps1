# CWFR Workyard: one-time, two-card approval only. 2026-11-20.
# Runs on the existing office Windows computer under the same user as Workyard MCP.
# NO credential export, account/connector changes, downloads, code installs or other timecard edits.
# Only PATCH /orgs/90001/time_cards/10000001/approve and /10000002/approve are permitted.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Net.Http
$Root = 'C:\Synthetic-PowerShell-Parser'
$Private = Join-Path $Root 'private'
$SettingsFile = Join-Path $Private 'settings.json'
$TokenFile = Join-Path $Private 'token.dpapi'
if (-not (Test-Path -LiteralPath $SettingsFile -PathType Leaf) -or -not (Test-Path -LiteralPath $TokenFile -PathType Leaf)) {
  throw 'EXISTING_WORKYARD_CREDENTIAL_STORE_UNAVAILABLE; nothing changed.'
}
$Settings = Get-Content -LiteralPath $SettingsFile -Raw | ConvertFrom-Json
if ([string]$Settings.org_id -cne '90001' -or [string]$Settings.api_base -cne 'https://api.workyard.com') {
  throw 'WRONG_ORGANIZATION_OR_API_ORIGIN; nothing changed.'
}
$Secure = ConvertTo-SecureString -String (Get-Content -LiteralPath $TokenFile -Raw).Trim()
$Ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
try { $Token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($Ptr) }
finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Ptr) }
if ([string]::IsNullOrWhiteSpace($Token)) { throw 'WORKYARD_CREDENTIAL_EMPTY; nothing changed.' }
$Handler = New-Object System.Net.Http.HttpClientHandler
$Handler.AllowAutoRedirect = $false
$Client = [System.Net.Http.HttpClient]::new($Handler)
$Client.Timeout = [TimeSpan]::FromSeconds(30)
$Client.DefaultRequestHeaders.Authorization = [System.Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $Token)
$Client.DefaultRequestHeaders.Accept.Add(([System.Net.Http.Headers.MediaTypeWithQualityHeaderValue]::new('application/json')))
Remove-Variable Token, Secure, Ptr -ErrorAction SilentlyContinue

function Invoke-ExactWorkyard([string]$Method, [int]$Id) {
  if ($Id -notin @(10000001,10000002) -or $Method -notin @('GET','PATCH')) { throw 'UNEXPECTED_REQUEST_DENIED' }
  $Uri = 'https://api.workyard.com/orgs/90001/time_cards/' + $Id
  if ($Method -eq 'GET') { $Uri += '?include=cost_allocations,notes' }
  else { $Uri += '/approve' }
  $Msg = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::new($Method),[Uri]::new($Uri))
  try {
    $Resp = $Client.SendAsync($Msg).GetAwaiter().GetResult()
    try {
      if (-not $Resp.IsSuccessStatusCode -or [int]$Resp.StatusCode -ne 200) {
        throw ('WORKYARD_HTTP_' + [int]$Resp.StatusCode + ' for card ' + $Id + '; do not automatically retry approvals.')
      }
      if ($Method -eq 'PATCH') { return $true }
      $Body = $Resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
      if ($Body.Length -gt 2000000) { throw 'UNEXPECTED_WORKYARD_RESPONSE_SIZE' }
      $Obj = $Body | ConvertFrom-Json
      if ($null -ne $Obj.PSObject.Properties['data'] -and $null -ne $Obj.data -and $null -ne $Obj.data.PSObject.Properties['id']) { $Obj = $Obj.data }
      return $Obj
    } finally { $Resp.Dispose() }
  } finally { $Msg.Dispose() }
}

$Expected = @(
  @{ id=10000001; name='Synthetic Employee A'; worker=200001; updated=1700000001; start=1699998000; end=1700034840; seconds=36000; at=36000; outside=0; driving=0 },
  @{ id=10000002; name='Synthetic Employee B'; worker=200002; updated=1700000002; start=1699999200; end=1700029560; seconds=30000; at=20000; outside=6000; driving=4000 }
)
function Verify-SubmittedCard($E) {
  $C = Invoke-ExactWorkyard 'GET' $E.id
  if ([int]$C.id -ne $E.id -or [int]$C.employee_id -ne $E.worker -or [string]$C.worker.display_name -cne $E.name) { throw ('CARD_IDENTITY_CHANGED_' + $E.id) }
  if ([string]$C.status -cne 'submitted' -or $C.is_approvable -ne $true) { throw ('CARD_NOT_READY_' + $E.id) }
  if ([int64]$C.updated_at_unix -ne $E.updated -or [int64]$C.start_dt_unix -ne $E.start -or [int64]$C.end_dt_unix -ne $E.end) { throw ('CARD_CHANGED_SINCE_REVIEW_' + $E.id) }
  if ([string]$C.timezone -cne 'America/New_York' -or [int]$C.time_summary.duration_secs -ne $E.seconds) { throw ('CARD_TIME_MISMATCH_' + $E.id) }
  if ($null -eq $C.PSObject.Properties['alerts'] -or @($C.alerts | Where-Object { $null -ne $_ }).Count -ne 0 -or $null -ne $C.update_warning) { throw ('CARD_ALERT_OR_WARNING_' + $E.id) }
  if ($null -eq $C.PSObject.Properties['notes'] -or @($C.notes | Where-Object { $null -ne $_ }).Count -ne 0 -or [int]$C.note_count -ne 0) { throw ('CARD_NOTES_REQUIRE_REVIEW_' + $E.id) }
  $Signed = @($C.work_form_submissions | Where-Object { $_.type -ceq 'time-card-sign-off' -and [int]$_.unexpected_answers_count -eq 0 })
  if ($Signed.Count -lt 1) { throw ('CARD_SIGNOFF_MISSING_' + $E.id) }
  $A = @($C.cost_allocations | Where-Object { $null -ne $_ })
  if ($A.Count -ne 1 -or [int]$A[0].org_project_id -ne 300001 -or [int]$A[0].duration_secs -ne $E.seconds -or $null -ne $A[0].job_code_id) { throw ('CARD_ALLOCATION_CHANGED_' + $E.id) }
  $M = $A[0].parsed_metadata
  if ($null -eq $M -or [int]$M.at_project_time_secs -ne $E.at -or [int]$M.outside_project_time_secs -ne $E.outside -or [int]$M.driving_time_secs -ne $E.driving) { throw ('CARD_ACTIVITY_CHANGED_' + $E.id) }
  return $C
}
try {
  # Both cards must pass full read-only review before the first effect.
  foreach ($E in $Expected) { [void](Verify-SubmittedCard $E) }
  Write-Output 'BOTH_CARD_PREFLIGHTS_PASSED: No time or allocation edits required.'
  foreach ($E in $Expected) {
    # Recheck immediately prior to the one-time PATCH.
    [void](Verify-SubmittedCard $E)
    $Claim = Join-Path $Private ('approval_20261119_' + $E.id + '.intent')
    $Bytes = [Text.Encoding]::UTF8.GetBytes(('one-time card approval; employee='+$E.name+'; expected_revision='+$E.updated+'; UTC='+[DateTime]::UtcNow.ToString('o')))
    $Stream = [IO.File]::Open($Claim,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $Stream.Write($Bytes,0,$Bytes.Length); $Stream.Flush($true) }
    finally { $Stream.Dispose() }
    # No automatic retry under any circumstances: 429, timeout or uncertain outcome.
    [void](Invoke-ExactWorkyard 'PATCH' $E.id)
    $After = Invoke-ExactWorkyard 'GET' $E.id
    if ([int]$After.id -ne $E.id -or [string]$After.status -cne 'approved' -or [int64]$After.start_dt_unix -ne $E.start -or [int64]$After.end_dt_unix -ne $E.end -or [int]$After.time_summary.duration_secs -ne $E.seconds) {
      throw ('APPROVAL_READBACK_UNCERTAIN_' + $E.id + '; no retry')
    }
    Write-Output ('VERIFIED_APPROVED: '+$E.name+'; 2026-11-19; '+[int]($E.seconds / 60)+' minutes; card '+$E.id)
  }
  Write-Output 'BOTH_APPROVALS_VERIFIED: Workyard readback shows both Approved.'
} finally {
  $Client.Dispose()
  $Handler.Dispose()
}