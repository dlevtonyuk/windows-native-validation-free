import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {handleOwnerStage} from './owner_stage.mjs';
import gateway from './worker.mjs';

const now=Date.parse('2026-11-11T16:00:00Z');
const origin='https://owner-stage.example.invalid';
const ownerEmail='owner@example.invalid';
const {privateKey,publicKey}=generateKeyPairSync('ed25519');
const rawKey=publicKey.export({type:'spki',format:'der'}).subarray(-32).toString('base64');
const policy=(revision=1,enabled=false)=>({version:1,owner:'local_owner',revision,
 expires_utc:new Date(now+86400000).toISOString(),
 capabilities:{synthetic_probe:{enabled,devices:['cloud_runner'],operations:['echo']}}});
const signed=(p=policy())=>{const raw=JSON.stringify(p);return {policy_json:raw,
 signature_b64:sign(null,Buffer.from(raw),privateKey).toString('base64')}};
class MockD1{
 constructor(){this.row=null;this.writes=0}
 prepare(sql){
   assert.match(sql,/owner_policy_stage/);
   assert.match(sql,/excluded.revision>owner_policy_stage.revision/);
   return {bind:(revision,policy_json,signature_b64,digest_hex,actor_sha256,staged_at)=>({
     first:async()=>{
       if(this.row&&this.row.revision>=revision)return null;
       this.row={revision,policy_json,signature_b64,digest_hex,actor_sha256,staged_at};
       this.writes++;return this.row;
     }
   })};
 }
}
const db=new MockD1();
const env=()=>({DB:db,OWNER_PUBLIC_KEY_B64:rawKey,
 OWNER_ACCESS_AUD:'synthetic-access-audience',OWNER_ACCESS_EMAIL:ownerEmail});
const ctx=()=>({access:{aud:'synthetic-access-audience',getIdentity:async()=>({email:ownerEmail})}});
const request=(payload=signed(),headers={},url=origin+'/owner/policy/stage',method='POST')=>
 new Request(url,{method,headers:{origin,'content-type':'application/json',...headers},
 body:method==='POST'?JSON.stringify(payload):undefined});
const run=(req=request(),e=env(),c=ctx())=>handleOwnerStage(req,e,c,{now});

test('irrelevant routes pass through and original health contract persists',async()=>{
 assert.equal(await run(new Request(origin+'/health')),null);
 const res=await gateway.fetch(new Request(origin+'/health'),{});
 assert.equal(res.status,200);
 assert.deepEqual(await res.json(),{service:'universal-gateway',status:'no_public_capabilities'});
});
test('missing Cloudflare Access identity fails closed before D1',async()=>{
 db.row=null;db.writes=0;
 assert.equal((await run(request(),env(),{})).status,403);
 assert.equal((await gateway.fetch(request(),env(),{})).status,403);
 assert.equal(db.writes,0);
});
test('Access audience, identity and getIdentity failure reject owner staging',async()=>{
 for(const fake of [
   {access:{aud:'wrong',getIdentity:async()=>({email:ownerEmail})}},
   {access:{aud:'synthetic-access-audience',getIdentity:async()=>({email:'intruder@example.invalid'})}},
   {access:{aud:'synthetic-access-audience',getIdentity:async()=>{throw Error('auth unavailable')}}},
   {access:{aud:'synthetic-access-audience',getIdentity:async()=>({email:null})}},
 ]){
   assert.equal((await run(request(),env(),fake)).status,403);
 }
 assert.equal(db.writes,0);
});
test('cross-site, missing origin and non-JSON requests are rejected',async()=>{
 for(const headers of [
   {origin:'https://other.example.invalid'},{origin:''},
   {'sec-fetch-site':'cross-site'},{'content-type':'text/plain'}
 ]) assert.equal((await run(request(signed(),headers))).status,403);
 assert.equal(db.writes,0);
});
test('valid signed disabled owner policy is staged, not activated',async()=>{
 const r=await run();
 assert.equal(r.status,202);
 const body=await r.json();
 assert.equal(body.state,'staged_disabled');
 assert.equal(body.revision,1);
 assert.equal(db.row.revision,1);
 assert.equal(db.row.actor_sha256.length,64);
 assert.equal(JSON.parse(db.row.policy_json).capabilities.synthetic_probe.enabled,false);
 assert.equal(db.writes,1);
});
test('replayed revision and older signed revisions are rejected atomically',async()=>{
 assert.equal((await run()).status,409);
 assert.equal((await run(request(signed(policy(2))))).status,202);
 assert.equal((await run(request(signed(policy(1))))).status,409);
 assert.equal(db.row.revision,2);
});
test('signed enabled or broader policies are not accepted',async()=>{
 assert.equal((await run(request(signed(policy(3,true))))).status,400);
 let broad=policy(3);broad.capabilities.windows_diagnostics={enabled:false,operations:['snapshot'],devices:['office_pc']};
 assert.equal((await run(request(signed(broad)))).status,400);
 assert.equal(db.row.revision,2);
});
test('tampered signatures, bad base64 and invalid pinned owner key reject',async()=>{
 const tampered=signed(policy(3));tampered.policy_json=tampered.policy_json.replace('"revision":3','"revision":4');
 assert.equal((await run(request(tampered))).status,403);
 const bad=env();bad.OWNER_PUBLIC_KEY_B64='%%%';
 assert.equal((await run(request(signed(policy(3))),bad)).status,400);
 assert.equal(db.row.revision,2);
});
test('expiry, non-canonical policy and extra capability keys denied',async()=>{
 const expired=policy(3);expired.expires_utc=new Date(now-1000).toISOString();
 assert.equal((await run(request(signed(expired)))).status,400);
 const late=policy(3);late.expires_utc=new Date(now+91*86400000).toISOString();
 assert.equal((await run(request(signed(late)))).status,400);
 const extra=policy(3);extra.unknown=true;
 assert.equal((await run(request(signed(extra)))).status,400);
});
test('oversized request and declared length are rejected without DB changes',async()=>{
 const tooBig=new Request(origin+'/owner/policy/stage',{method:'POST',
   headers:{origin,'content-type':'application/json'},body:' '.repeat(8193)});
 assert.equal((await run(tooBig)).status,400);
 assert.equal((await run(request(signed(),{'content-length':'200000'}))).status,400);
 assert.equal(db.row.revision,2);
});
test('owner routes other than explicit staging endpoint return 404',async()=>{
 assert.equal((await run(new Request(origin+'/owner/enable'))).status,404);
 assert.equal((await run(request(signed(),{},origin+'/owner/policy/stage','GET'))).status,404);
 assert.equal(db.row.revision,2);
});
test('missing database is explicitly unavailable, with no fallback to jobs table',async()=>{
 const e=env();delete e.DB;
 assert.equal((await run(request(signed(policy(3))),e)).status,503);
});
test('signed valid policy is not enough without real ctx.access',async()=>{
 const fake={...env(),OWNER_PUBLIC_KEY_B64:rawKey};
 const response=await gateway.fetch(request(signed(policy(3))),fake,{});
 assert.equal(response.status,403);
});
