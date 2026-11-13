import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {verifyOwnerEffectGrant,executeOwnerApprovedEffect} from './owner_effect_gate.mjs';

const pair=generateKeyPairSync('ed25519');  // Synthetic disposable key only.
const key=pair.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64');
const now=Date.UTC(2026,10,13,16,0,0);
const payload=Buffer.from('{"synthetic":"diagnostic"}','utf8');
const hash=createHash('sha256').update(payload).digest('hex');
const lease=(over={})=>({version:1,owner:'local_owner',gateway_id:'main_gateway',
 device_id:'synthetic_device',capability:'synthetic_diagnostic',operation:'fixed_read',
 payload_sha256:hash,revision:7,max_claims:3,
 issued_utc:new Date(now-60_000).toISOString(),expires_utc:new Date(now+3600_000).toISOString(),...over});
const signed=(m)=>{const grant_json=JSON.stringify(m);return {grant_json,signature_b64:sign(null,Buffer.from(grant_json),pair.privateKey).toString('base64')}};
const context={pinnedOwnerPublicKeyB64:key,gatewayId:'main_gateway',deviceId:'synthetic_device',capability:'synthetic_diagnostic',operation:'fixed_read',activeRevision:7,nowMs:now};
const verify=(m,ctx={})=>verifyOwnerEffectGrant(signed(m),{...context,...ctx});

test('verifies owner-signed narrowly pinned lease',()=>{
 const g=verify(lease());assert.equal(g.grant_sha256.length,64);assert.equal(g.payload_sha256,hash);
 assert.equal(g.max_claims,3);assert.equal(g.revision,7);
});
test('rejects scope substitution and stale activation',()=>{
 for(const [prop,value] of [['gatewayId','other_gateway'],['deviceId','other_device'],['capability','payroll_write'],['operation','execute_shell'],['activeRevision',8]]){
  assert.throws(()=>verify(lease(),{[prop]:value}),/scope_mismatch|stale_or_unactivated/);
 }
});
test('forged or mutated owner signature is rejected',()=>{
 const env=signed(lease());env.grant_json=env.grant_json.replace('"max_claims":3','"max_claims":100');
 assert.throws(()=>verifyOwnerEffectGrant(env,context),/owner_signature_invalid/);
 const env2=signed(lease());env2.signature_b64='A'.repeat(88);
 assert.throws(()=>verifyOwnerEffectGrant(env2,context),/malformed_base64|owner_signature_invalid/);
});
test('rejects extra capability, commands, or unknown grant fields',()=>{
 assert.throws(()=>verify({...lease(),shell:true}),/unexpected_fields/);
 assert.throws(()=>verify(lease({operation:'execute_shell'})),/scope_mismatch/);
});
test('rejects lifetime overflow, stale grant, and future issue',()=>{
 assert.throws(()=>verify(lease({expires_utc:new Date(now+31*86400000).toISOString()})),/grant_expired_or_invalid_clock/);
 assert.throws(()=>verify(lease({expires_utc:new Date(now-1000).toISOString()})),/grant_expired_or_invalid_clock/);
 assert.throws(()=>verify(lease({issued_utc:new Date(now+3600000).toISOString()})),/grant_expired_or_invalid_clock/);
});
test('requires valid signed payload pin and strict claim budget',()=>{
 assert.throws(()=>verify(lease({max_claims:10001})),/invalid_claim_budget/);
 assert.throws(()=>verify(lease({max_claims:true})),/invalid_claim_budget/);
 assert.throws(()=>verify(lease({payload_sha256:'bad'})),/invalid_payload_pin/);
});
test('rejects attacker key, wrong grant identity and unexpected envelope fields',()=>{
 const other=generateKeyPairSync('ed25519').publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64');
 assert.throws(()=>verify(lease(),{pinnedOwnerPublicKeyB64:other}),/owner_signature_invalid/);
 assert.throws(()=>verify(lease({owner:'assistant'})),/invalid_grant_identity/);
 assert.throws(()=>verifyOwnerEffectGrant({...signed(lease()),bypass:true},context),/unexpected_fields/);
});
function fakeStore(max=3){
 const jobs=new Map();let count=0;return {jobs,
  async reserve(x){if(jobs.has(x.job_id))throw Error('effect_replay_blocked');if(count>=max)throw Error('grant_budget_exhausted');
    count++;jobs.set(x.job_id,'reserved');return {state:'reserved',job_id:x.job_id}},
  async finalize(x){if(jobs.get(x.job_id)!=='reserved')throw Error('finalize_not_reserved');jobs.set(x.job_id,x.outcome)}};
}
test('trusted handler receives only signed fixed bytes, one use',async()=>{
 const grant=verify(lease());const store=fakeStore();let calls=0;
 const run=()=>executeOwnerApprovedEffect({envelope:signed(lease()),context,jobId:'a'.repeat(32),payloadBytes:payload,store,nowMs:now,handler:async p=>{calls++;assert.deepEqual(p,payload);return 'synthetic_ok'}});
 assert.equal(await run(),'synthetic_ok');await assert.rejects(run(),/effect_replay_blocked/);
 assert.equal(calls,1);assert.equal(store.jobs.get('a'.repeat(32)),'succeeded');
});
test('mutated payload fails before reserve and handler',async()=>{
 const grant=verify(lease());const store=fakeStore();let calls=0;
 await assert.rejects(executeOwnerApprovedEffect({envelope:signed(lease()),context,jobId:'a'.repeat(32),payloadBytes:Buffer.from('malicious shell'),store,nowMs:now,handler:async()=>{calls++}}),/effect_payload_not_authorized/);
 assert.equal(store.jobs.size,0);assert.equal(calls,0);
});
test('expired lease fails before any effect',async()=>{
 const grant=verify(lease());const store=fakeStore();let called=false;
 await assert.rejects(executeOwnerApprovedEffect({envelope:signed(lease()),context,jobId:'a'.repeat(32),payloadBytes:payload,store,nowMs:now+7200000,handler:async()=>{called=true}}),/grant_expired/);
 assert.equal(called,false);assert.equal(store.jobs.size,0);
});
test('failed handler consumes reservation and is not retried',async()=>{
 const grant=verify(lease());const store=fakeStore();let calls=0;
 const run=()=>executeOwnerApprovedEffect({envelope:signed(lease()),context,jobId:'b'.repeat(32),payloadBytes:payload,store,nowMs:now,handler:async()=>{calls++;throw Error('synthetic_failure')}});
 await assert.rejects(run(),/synthetic_failure/);await assert.rejects(run(),/effect_replay_blocked/);
 assert.equal(calls,1);assert.equal(store.jobs.get('b'.repeat(32)),'failed');
});

test('public execution API rechecks signature; forged grant cannot reach handler',async()=>{
 const store=fakeStore();let called=false;
 const forged=signed(lease());forged.grant_json=forged.grant_json.replace('"max_claims":3','"max_claims":100');
 await assert.rejects(executeOwnerApprovedEffect({envelope:forged,context,jobId:'a'.repeat(32),payloadBytes:payload,store,nowMs:now,handler:async()=>{called=true}}),/owner_signature_invalid/);
 assert.equal(called,false);assert.equal(store.jobs.size,0);
});
test('invalid calendar date is rejected before handler',()=>{
 assert.throws(()=>verify(lease({issued_utc:'2026-02-30T12:00:00.000Z'})),/invalid_lease_date/);
});

// Cross-language integration uses a disposable, real SQLite host ledger on
// native Windows/Linux; the fixture passes NO remotely supplied Python code.
const cwd=dirname(fileURLToPath(import.meta.url));
const PY=`import json,sys
from owner_effect_ledger import initialize,activate,reserve,finalize,status
p=json.loads(sys.argv[1]);cmd=p.pop('action');db=p.pop('db')
if cmd=='init':result=initialize(db) or {'state':'initialized'}
elif cmd=='activate':result=activate(db,**p)
elif cmd=='reserve':result=reserve(db,**p)
elif cmd=='finalize':result=finalize(db,**p)
elif cmd=='status':result=status(db)
else:raise SystemExit(8)
print(json.dumps(result))`;
function pythonAction(action,db,opts={}) {
 const p=spawnSync('python',['-c',PY,JSON.stringify({action,db,...opts})],{cwd,encoding:'utf8',timeout:10000});
 if(p.error)throw p.error;
 if(p.status!==0)throw Error(`trusted_ledger_denied:${p.stderr.slice(0,200)}`);
 return JSON.parse(p.stdout);
}
function realStore(db){
 return {
  reserve: x=>Promise.resolve(pythonAction('reserve',db,x)),
  finalize: x=>Promise.resolve(pythonAction('finalize',db,{job_id:x.job_id,outcome:x.outcome}))
 };
}
test('end-to-end signed grant, real SQLite reservation, replay denial across processes',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'uag-effect-fence-'));
 try {
  const db=join(dir,'trusted-effect.sqlite');const grant=verify(lease());
  pythonAction('init',db);
  pythonAction('activate',db,{revision:grant.revision,grant_sha256:grant.grant_sha256,max_claims:grant.max_claims});
  let calls=0;
  const run=(jobId,store=realStore(db))=>executeOwnerApprovedEffect({
   envelope:signed(lease()),context,jobId,payloadBytes:payload,store,nowMs:now,
   handler:async()=>{calls++;return 'inert'}});
  assert.equal(await run('1'.repeat(32)),'inert');
  await assert.rejects(run('1'.repeat(32),realStore(db)),/trusted_ledger_denied/);
  assert.equal(await run('2'.repeat(32)),'inert');
  assert.equal(await run('3'.repeat(32)),'inert');
  await assert.rejects(run('4'.repeat(32)),/trusted_ledger_denied/);
  assert.equal(calls,3);
  assert.equal(pythonAction('status',db).active.claimed,3);
 } finally {rmSync(dir,{recursive:true,force:true});}
});
test('a missing trusted SQLite ledger denies signed request before handler',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'uag-effect-fence-'));
 try {
  const db=join(dir,'does-not-exist.sqlite');let calls=0;
  await assert.rejects(executeOwnerApprovedEffect({envelope:signed(lease()),context,
   jobId:'f'.repeat(32),payloadBytes:payload,store:realStore(db),nowMs:now,
   handler:async()=>{calls++}}),/trusted_ledger_denied/);
  assert.equal(calls,0);
 } finally {rmSync(dir,{recursive:true,force:true});}
});
