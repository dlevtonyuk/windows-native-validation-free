import test from 'node:test';
import assert from 'node:assert/strict';
import {verifyFoundationReadOnly,estimateOwnerRunnerMinutes} from './foundation_read_only.mjs';
const accountId='a'.repeat(32), databaseId='00000000-0000-4000-8000-000000000000',token='f'.repeat(40);
const caps=[
 {capability_id:'chatgpt_connector',route:'connector_readonly',enabled:0,owner_activation_revision:0},
 {capability_id:'cloud_read_adapter',route:'cloud_readonly',enabled:0,owner_activation_revision:0},
 {capability_id:'device_service',route:'device_local',enabled:0,owner_activation_revision:0},
 {capability_id:'owner_effect_broker',route:'owner_guarded_effect',enabled:0,owner_activation_revision:0}
];
const fixtures=[
 [{schema_version:1,execution_mode:'FOUNDATION_INERT'}],
 caps,
 [{state:'cancelled',n:1}],
 [{n:2,last_slot:1794836100000}]
];
function provider(data=fixtures,failAt=-1){
 const calls=[];
 const fetcher=async(url,options)=>{
  assert.equal(new URL(url).origin,'https://api.cloudflare.com');
  assert.equal(new URL(url).pathname,'/client/v4/accounts/'+accountId+'/d1/database/'+databaseId+'/query');
  assert.equal(options.method,'POST');
  assert.equal(options.redirect,'error');
  assert.equal(options.headers.Authorization,'Bearer '+token);
  const parsed=JSON.parse(options.body);
  assert.ok(parsed.sql.trim().startsWith('SELECT '));
  assert.ok(!/DELETE|UPDATE|INSERT|PRAGMA|ALTER|DROP/i.test(parsed.sql));
  const i=calls.length;calls.push(parsed.sql);
  if(i===failAt)return {status:403,json:async()=>({success:false})};
  return {status:200,json:async()=>({success:true,result:[{success:true,results:data[i]}]})};
 };
 return {fetcher,calls};
}
const run=fetcher=>verifyFoundationReadOnly({fetcher,apiToken:token,accountId,databaseId});
test('owner runner reads four fixed SELECT statements and returns aggregates only',async()=>{
 const p=provider();const r=await run(p.fetcher);
 assert.equal(p.calls.length,4);
 assert.equal(r.kind,'owner_runner_foundation_read_probe');
 assert.equal(r.enabled_capabilities,0);
 assert.equal(r.cron_receipts,2);
 assert.equal(r.held_job_count,0);
 assert.equal(r.execution,'NONE');
 assert.equal(JSON.stringify(r).includes('Authorization'),false);
});
test('a compromised untrusted queue cannot turn held capability into effect',async()=>{
 const data=structuredClone(fixtures);
 data[1][3].enabled=1;
 await assert.rejects(run(provider(data).fetcher),/unexpected_capability_activation/);
 data[1][3].enabled=0;data[2].push({state:'running',n:1});
 await assert.rejects(run(provider(data).fetcher),/unexpected_queue_state/);
});
test('invalid raw credential and resource IDs fail before any network call',async()=>{
 let requests=0;
 const f=()=>{requests++;throw Error('unexpected network')};
 await assert.rejects(verifyFoundationReadOnly({fetcher:f,apiToken:token,accountId:'INVALID',databaseId}),/invalid_resource_identifier/);
 await assert.rejects(verifyFoundationReadOnly({fetcher:f,apiToken:'',accountId,databaseId}),/credential_unavailable/);
 assert.equal(requests,0);
});
test('owner runner fails closed on API errors, schema changes and duplicate capability',async()=>{
 await assert.rejects(run(provider(fixtures,2).fetcher),/d1_read_http_403/);
 const d=structuredClone(fixtures);d[0][0].execution_mode='ENABLED';
 await assert.rejects(run(provider(d).fetcher),/unexpected_foundation_mode/);
 const x=structuredClone(fixtures);x[1][3].capability_id=x[1][0].capability_id;
 await assert.rejects(run(provider(x).fetcher),/invalid_capability_row/);
});
test('hourly on 31-day month fits nominal 2000-minute quota but unknown usage must be verified',()=>{
 const r=estimateOwnerRunnerMinutes();
 assert.equal(r.projectedMonthlyMinutes,744);
 assert.equal(r.headroomLimit,1600);
 assert.equal(r.admissible,true);
 assert.equal(estimateOwnerRunnerMinutes({otherPrivateMinutes:900}).admissible,false);
 assert.equal(estimateOwnerRunnerMinutes({runsPerDay:288}).admissible,false);
 assert.throws(()=>estimateOwnerRunnerMinutes({minutesPerRun:-1}),/budget_invalid/);
});
