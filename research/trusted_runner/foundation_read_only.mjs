// RESEARCH ONLY: candidate owner-controlled PRIVATE GitHub Actions runner.
// This module reads only aggregate, synthetic UAG foundation metadata from D1.
// Never import code dynamically from the assistant-editable development repository.
// Any deploy/secret-bearing source must be copied and pinned by the owner in a
// private repository NOT visible to connected ChatGPT GitHub apps.
// No business APIs, credentials, private worker updates, or effect operations.
const ONLY_ORIGIN='https://api.cloudflare.com';
const SAFE_ID=/^[a-z][a-z0-9_-]{2,63}$/;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SQL=Object.freeze({
  meta:"SELECT schema_version, execution_mode FROM foundation_meta WHERE id=1",
  state:"SELECT capability_id, route, enabled, owner_activation_revision FROM foundation_capabilities ORDER BY capability_id",
  queue:"SELECT state, COUNT(*) AS n FROM foundation_jobs GROUP BY state ORDER BY state",
  receipts:"SELECT COUNT(*) AS n, MAX(slot_ms) AS last_slot FROM foundation_ticks"
});
const ROUTES=new Set(['cloud_readonly','connector_readonly','device_local','owner_guarded_effect']);
function error(code){const e=new Error(code);e.code=code;return e}
function token(value){if(typeof value!=='string'||value.length<20||value.length>512)throw error('credential_unavailable');return value}
function assertEnvelope(body){
  if(!body||body.success!==true||!Array.isArray(body.result)||body.result.length!==1||body.result[0].success!==true||!Array.isArray(body.result[0].results))throw error('d1_result_untrusted');
  return body.result[0].results;
}
function validateRows(groups){
  const meta=groups.meta;
  if(meta.length!==1||meta[0].schema_version!==1||meta[0].execution_mode!=='FOUNDATION_INERT')throw error('unexpected_foundation_mode');
  const caps=groups.state;
  const seen=new Set();
  if(caps.length!==4)throw error('unexpected_capability_catalog');
  for(const c of caps){
    if(!c||typeof c.capability_id!=='string'||!SAFE_ID.test(c.capability_id)||seen.has(c.capability_id)||!ROUTES.has(c.route))throw error('invalid_capability_row');
    seen.add(c.capability_id);
    if(c.enabled!==0||c.owner_activation_revision!==0)throw error('unexpected_capability_activation');
  }
  let jobs=0;
  for(const q of groups.queue){
    if(!q||!['held','cancelled'].includes(q.state)||!Number.isSafeInteger(q.n)||q.n<0)throw error('unexpected_queue_state');
    if(q.state==='held')jobs+=q.n;
  }
  const r=groups.receipts;
  if(r.length!==1||!Number.isSafeInteger(r[0].n)||r[0].n<0)throw error('invalid_receipt_count');
  if(r[0].last_slot!==null&&(!Number.isSafeInteger(r[0].last_slot)||r[0].last_slot<=0))throw error('invalid_receipt_clock');
  return Object.freeze({kind:'owner_runner_foundation_read_probe',execution:'NONE',
    owner_only_activation_status:'NOT_PROVISIONED',capability_count:caps.length,
    enabled_capabilities:0,held_job_count:jobs,cron_receipts:r[0].n,latest_cron_slot_ms:r[0].last_slot});
}
export async function verifyFoundationReadOnly({fetcher,apiToken,accountId,databaseId}){
  if(typeof fetcher!=='function')throw error('transport_missing');
  if(typeof accountId!=='string'||!/^[a-f0-9]{32}$/i.test(accountId)||
     typeof databaseId!=='string'||!UUID.test(databaseId))throw error('invalid_resource_identifier');
  const secret=token(apiToken);
  const path='/client/v4/accounts/'+accountId+'/d1/database/'+databaseId+'/query';
  const collected={};
  for(const [kind,sql] of Object.entries(SQL)){
    const u=new URL(path,ONLY_ORIGIN);
    if(u.origin!==ONLY_ORIGIN||u.pathname!==path)throw error('invalid_api_target');
    const res=await fetcher(u.toString(),{
      method:'POST',redirect:'error',
      headers:{Authorization:'Bearer '+secret,Accept:'application/json','Content-Type':'application/json'},
      body:JSON.stringify({sql})
    });
    if(!res||!Number.isInteger(res.status))throw error('invalid_api_response');
    if(res.status!==200)throw error('d1_read_http_'+res.status);
    collected[kind]=assertEnvelope(await res.json());
  }
  return validateRows(collected);
}
export function estimateOwnerRunnerMinutes({runsPerDay=24,minutesPerRun=1,otherPrivateMinutes=0,
  accountIncludedMinutes=2000,headroom=0.8}={}){
  for(const v of [runsPerDay,minutesPerRun,otherPrivateMinutes,accountIncludedMinutes])if(!Number.isSafeInteger(v)||v<0)throw error('budget_invalid');
  if(!(headroom>0&&headroom<=1))throw error('budget_invalid');
  const month=31; // worst normal calendar month, never optimistic average.
  const projected=runsPerDay*minutesPerRun*month+otherPrivateMinutes;
  if(!Number.isSafeInteger(projected))throw error('budget_overflow');
  return {projectedMonthlyMinutes:projected,headroomLimit:Math.floor(accountIncludedMinutes*headroom),
    admissible:projected<=accountIncludedMinutes*headroom,
    scheduleRequirement:'OWNER_PRIVATE_REPO_ONLY',
    caveat:'Source plan entitlement and account-wide consumed minutes must be owner-verified; this is a worst-31-day estimate, not a measured bill.'};
}
