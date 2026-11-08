import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import gateway from "./worker.mjs";

if (!globalThis.crypto) globalThis.crypto = webcrypto;
const b64 = bytes => Buffer.from(bytes).toString("base64");
const TOKEN = "dummy-submit-token-for-public-tests-only-00000001";
const DEVICE = "dummy-device-token-for-public-tests-only-0000001";

class MockD1 {
  constructor() { this.jobs = new Map(); this.policyState = null; this.policyRevisionWrites=0; }
  prepare(sql) {
    const db=this;
    return { bind(...args) { return {
      async run() {
        if (sql.startsWith("UPDATE jobs SET state='interrupted' WHERE state='leased'")) {
          const [now,device]=args;
          for (const row of db.jobs.values())
            if (row.state==="leased"&&row.lease_until<now&&row.device===device)
              row.state="interrupted";
          return {success:true};
        }
        if (sql.startsWith("UPDATE jobs SET state='interrupted' WHERE job_id=?")) {
          const row=db.jobs.get(args[0]);
          if (row?.state==="leased") row.state="interrupted";
          return {success:true};
        }
        if (!sql.startsWith("INSERT INTO jobs")) throw Error("unexpected SQL");
        const [id,cap,op,device,payload,created] = args;
        if (db.jobs.has(id)) throw Error("duplicate");
        db.jobs.set(id,{job_id:id,capability:cap,operation:op,device,
                        payload_json:payload,created_at:created,state:"queued"});
        return {success:true};
      },
      async first() {
        if (sql.startsWith("INSERT INTO jobs")) {
          const [id,cap,op,device,payload,created,revision,digest]=args;
          if (db.policyState?.revision!==revision||db.policyState?.digest!==digest)
            return null;
          if (db.jobs.has(id)) throw Error("duplicate");
          db.jobs.set(id,{job_id:id,capability:cap,operation:op,device,
            payload_json:payload,created_at:created,state:"queued"});
          return {job_id:id};
        }
        if (sql.startsWith("SELECT 1 AS matched FROM owner_policy_state")) {
          return (db.policyState?.revision===args[0] &&
            db.policyState?.digest===args[1])?{matched:1}:null;
        }
        if (sql.startsWith("INSERT INTO owner_policy_state")) {
          const [revision,digest]=args;
          const previous=db.policyState;
          if (previous && revision<=previous.revision) return null;
          db.policyState={revision,digest};
          db.policyRevisionWrites++;
          return {highest_revision:revision};
        }
        if (sql.startsWith("SELECT highest_revision FROM owner_policy_state")) {
          return (db.policyState?.revision===args[0] &&
            db.policyState?.digest===args[1])?
            {highest_revision:args[0]}:null;
        }
        if (sql.startsWith("UPDATE jobs SET state='leased'")) {
          const [lease,device,revision,digest] = args;
          if (db.policyState?.revision!==revision||db.policyState?.digest!==digest)
            return null;
          const row=[...db.jobs.values()].filter(j=>j.state==="queued"&&j.device===device)
            .sort((a,b)=>a.created_at-b.created_at)[0];
          if (!row) return null;
          row.state="leased";row.lease_until=lease;
          return {...row};
        }
        if (sql.startsWith("SELECT capability,operation,device FROM jobs")) {
          const [id,device,now]=args;
          const row=db.jobs.get(id);
          return (row&&row.device===device&&row.state==="leased"&&
            row.lease_until>now)?{capability:row.capability,operation:row.operation,
              device:row.device}:null;
        }
        if (sql.startsWith("UPDATE jobs SET state='interrupted' WHERE job_id=?")) {
          const [id,device,now,revision,digest]=args;
          const row=db.jobs.get(id);
          if (!row || row.device!==device || row.state!=="leased" ||
              row.lease_until<=now || db.policyState?.revision!==revision ||
              db.policyState?.digest!==digest) return null;
          row.state="interrupted";return {job_id:id};
        }
        if (sql.startsWith("UPDATE jobs SET state=?")) {
          const [status,result,id,device,now,revision,digest]=args;
          const row=db.jobs.get(id);
          if (!row||row.device!==device||row.state!=="leased"||row.lease_until<=now ||
              db.policyState?.revision!==revision || db.policyState?.digest!==digest)
            return null;
          row.state=status;row.result_json=result;
          return {job_id:id};
        }
        throw Error("unexpected SQL");
      }
    };}};
  }
}
async function policyEnv(enabled=true) {
  const keys=await crypto.subtle.generateKey("Ed25519",true,["sign","verify"]);
  const grant={version:1,owner:"local_owner",revision:1,expires_utc:"2099-01-01T00:00:00Z",
    capabilities:{windows_diagnostics:{enabled,operations:["snapshot"],devices:["office_pc"]}}};
  const data=JSON.stringify(grant);
  const sig=await crypto.subtle.sign("Ed25519",keys.privateKey,new TextEncoder().encode(data));
  const pub=await crypto.subtle.exportKey("raw",keys.publicKey);
  return {DB:new MockD1(),OWNER_POLICY_JSON:data,OWNER_PUBLIC_KEY_B64:b64(pub),
    OWNER_POLICY_SIGNATURE_B64:b64(sig),SUBMIT_TOKEN:TOKEN,
    DEVICE_TOKENS_JSON:JSON.stringify({office_pc:DEVICE}),TEST_PRIVATE_KEY:keys.privateKey};
}
const url = (path) => "https://example.invalid" + path;
const req=(path,method="GET",body=null,token=null,device=null) => {
  const headers={};
  if (token) headers.authorization="Bearer "+token;
  if (device) headers["x-device-id"]=device;
  if (body!==null) headers["content-type"]="application/json";
  return new Request(url(path),{method,headers,body:body===null?undefined:JSON.stringify(body)});
};
const job=(id="job_001",op="snapshot")=>({job_id:id,capability:"windows_diagnostics",
  operation:op,device:"office_pc",payload:{}});

async function signRotatedPolicy(env,revision,enabled) {
  const data=JSON.parse(env.OWNER_POLICY_JSON);
  data.revision=revision;
  data.capabilities.windows_diagnostics.enabled=enabled;
  env.OWNER_POLICY_JSON=JSON.stringify(data);
  env.OWNER_POLICY_SIGNATURE_B64=b64(await crypto.subtle.sign("Ed25519",
    env.TEST_PRIVATE_KEY,new TextEncoder().encode(env.OWNER_POLICY_JSON)));
}

test("public health provides no private data",async()=>{
  const r=await gateway.fetch(req("/health"),{});
  assert.equal(r.status,200);
  assert.deepEqual(Object.keys(await r.json()).sort(),["service","status"]);
});
test("missing activation denies jobs",async()=>{
  const r=await gateway.fetch(req("/v1/jobs","POST",job(),TOKEN),{SUBMIT_TOKEN:TOKEN});
  assert.equal(r.status,503);
});
test("forged owner signature fails closed",async()=>{
  const env=await policyEnv();
  env.OWNER_POLICY_SIGNATURE_B64=b64(new Uint8Array(64));
  assert.equal((await gateway.fetch(req("/v1/jobs","POST",job(),TOKEN),env)).status,503);
});
test("disabled owner grant blocks even authenticated sender",async()=>{
  const env=await policyEnv(false);
  assert.equal((await gateway.fetch(req("/v1/jobs","POST",job(),TOKEN),env)).status,403);
});
test("remote sender without token denied",async()=>{
  const env=await policyEnv();
  assert.equal((await gateway.fetch(req("/v1/jobs","POST",job()),env)).status,401);
});
test("wrong operation denied despite valid token",async()=>{
  const env=await policyEnv();
  assert.equal((await gateway.fetch(req("/v1/jobs","POST",job("job_002","run_shell"),TOKEN),env)).status,403);
});
test("owner-signed allowed job is durably queued, not executed",async()=>{
  const env=await policyEnv();
  const r=await gateway.fetch(req("/v1/jobs","POST",job(),TOKEN),env);
  assert.equal(r.status,202);
  assert.equal(env.DB.jobs.get("job_001").state,"queued");
});
test("replays rejected",async()=>{
  const env=await policyEnv();
  await gateway.fetch(req("/v1/jobs","POST",job(),TOKEN),env);
  assert.equal((await gateway.fetch(req("/v1/jobs","POST",job(),TOKEN),env)).status,409);
});
test("device cannot claim without its own token",async()=>{
  const env=await policyEnv();
  await gateway.fetch(req("/v1/jobs","POST",job(),TOKEN),env);
  assert.equal((await gateway.fetch(req("/v1/device/claim?device=office_pc"),env)).status,401);
});
test("device claims and completes only its own leased job",async()=>{
  const env=await policyEnv();
  await gateway.fetch(req("/v1/jobs","POST",job(),TOKEN),env);
  const claim=await gateway.fetch(req("/v1/device/claim?device=office_pc","GET",null,DEVICE),env);
  assert.equal(claim.status,200);
  const claimed=await claim.json();
  assert.equal(claimed.job_id,"job_001");
  assert.equal(env.DB.jobs.get("job_001").state,"leased");
  const done={job_id:"job_001",state:"succeeded",result:{ram_used_percent:80}};
  const finished=await gateway.fetch(req("/v1/device/complete","POST",done,DEVICE,"office_pc"),env);
  assert.equal(finished.status,200);
  assert.equal(env.DB.jobs.get("job_001").state,"succeeded");
  assert.equal((await gateway.fetch(req("/v1/device/complete","POST",done,DEVICE,"office_pc"),env)).status,409);
});
test("offline device leaves jobs queued",async()=>{
  const env=await policyEnv();
  await gateway.fetch(req("/v1/jobs","POST",job(),TOKEN),env);
  assert.equal(env.DB.jobs.get("job_001").state,"queued");
});
test("no remote capability-toggle endpoint exists",async()=>{
  const env=await policyEnv();
  assert.equal((await gateway.fetch(req("/v1/enable","POST",{capability:"windows_diagnostics"},TOKEN),env)).status,404);
});
test("expired signed policy fails closed",async()=>{
  const env=await policyEnv();
  const original=JSON.parse(env.OWNER_POLICY_JSON);
  original.expires_utc="2020-01-01T00:00:00Z";
  const keyPair=await crypto.subtle.generateKey("Ed25519",true,["sign","verify"]);
  env.OWNER_PUBLIC_KEY_B64=b64(await crypto.subtle.exportKey("raw",keyPair.publicKey));
  env.OWNER_POLICY_JSON=JSON.stringify(original);
  env.OWNER_POLICY_SIGNATURE_B64=b64(await crypto.subtle.sign(
    "Ed25519",keyPair.privateKey,new TextEncoder().encode(env.OWNER_POLICY_JSON)));
  assert.equal((await gateway.fetch(req("/v1/jobs","POST",job(),TOKEN),env)).status,503);
});

test("expired lease quarantined, never blindly replayed",async()=>{
  const env=await policyEnv();
  await gateway.fetch(req("/v1/jobs","POST",job(),TOKEN),env);
  await gateway.fetch(req("/v1/device/claim?device=office_pc","GET",null,DEVICE),env);
  env.DB.jobs.get("job_001").lease_until=Date.now()-1000;
  const r=await gateway.fetch(req("/v1/device/claim?device=office_pc","GET",null,DEVICE),env);
  assert.equal(r.status,200);
  assert.equal((await r.json()).state,"empty");
  assert.equal(env.DB.jobs.get("job_001").state,"interrupted");
});

test("valid previous owner-signed policy cannot restore revoked grant", async()=>{
  const env=await policyEnv();
  const oldJSON=env.OWNER_POLICY_JSON;
  const oldSig=env.OWNER_POLICY_SIGNATURE_B64;
  assert.equal((await gateway.fetch(req("/v1/jobs","POST",job("job_r01"),TOKEN),env)).status,202);
  const newest=JSON.parse(oldJSON);
  newest.revision=2;
  newest.capabilities.windows_diagnostics.enabled=false;
  env.OWNER_POLICY_JSON=JSON.stringify(newest);
  env.OWNER_POLICY_SIGNATURE_B64=b64(await crypto.subtle.sign(
    "Ed25519",env.TEST_PRIVATE_KEY,new TextEncoder().encode(env.OWNER_POLICY_JSON)));
  assert.equal((await gateway.fetch(req("/v1/jobs","POST",job("job_r02"),TOKEN),env)).status,403);
  env.OWNER_POLICY_JSON=oldJSON;
  env.OWNER_POLICY_SIGNATURE_B64=oldSig;
  assert.equal((await gateway.fetch(req("/v1/jobs","POST",job("job_r03"),TOKEN),env)).status,503);
});
test("same revision with different valid signed policy is rejected",async()=>{
  const env=await policyEnv();
  assert.equal((await gateway.fetch(req("/v1/jobs","POST",job("job_r04"),TOKEN),env)).status,202);
  const changed=JSON.parse(env.OWNER_POLICY_JSON);
  changed.capabilities.windows_diagnostics.enabled=false;
  env.OWNER_POLICY_JSON=JSON.stringify(changed);
  env.OWNER_POLICY_SIGNATURE_B64=b64(await crypto.subtle.sign(
    "Ed25519",env.TEST_PRIVATE_KEY,new TextEncoder().encode(env.OWNER_POLICY_JSON)));
  assert.equal((await gateway.fetch(req("/v1/jobs","POST",job("job_r05"),TOKEN),env)).status,503);
});
test("missing owner policy revision state fails closed",async()=>{
  const env=await policyEnv();
  env.DB.prepare=()=>{throw Error("missing owner_policy_state table")};
  assert.equal((await gateway.fetch(req("/v1/jobs","POST",job("job_r06"),TOKEN),env)).status,503);
});

test("revocation after lease quarantines completion instead of claiming success",async()=>{
  const env=await policyEnv();
  assert.equal((await gateway.fetch(req("/v1/jobs","POST",job("leased_r01"),TOKEN),env)).status,202);
  const claim=await gateway.fetch(req("/v1/device/claim?device=office_pc","GET",null,DEVICE),env);
  assert.equal(claim.status,200);
  assert.equal(env.DB.jobs.get("leased_r01").state,"leased");
  await signRotatedPolicy(env,2,false);
  const done={job_id:"leased_r01",state:"succeeded",result:{ram_used_percent:80}};
  const refused=await gateway.fetch(req("/v1/device/complete","POST",done,DEVICE,"office_pc"),env);
  assert.equal(refused.status,403);
  assert.equal((await refused.json()).error,"grant_revoked_after_lease");
  assert.equal(env.DB.jobs.get("leased_r01").state,"interrupted");
  assert.equal((await gateway.fetch(req("/v1/device/complete","POST",done,DEVICE,"office_pc"),env)).status,409);
});
test("renewed authorized lease completion works with newer signed policy",async()=>{
  const env=await policyEnv();
  await gateway.fetch(req("/v1/jobs","POST",job("leased_r02"),TOKEN),env);
  assert.equal((await gateway.fetch(req("/v1/device/claim?device=office_pc","GET",null,DEVICE),env)).status,200);
  await signRotatedPolicy(env,2,true);
  const done={job_id:"leased_r02",state:"succeeded",result:{}};
  assert.equal((await gateway.fetch(req("/v1/device/complete","POST",done,DEVICE,"office_pc"),env)).status,200);
  assert.equal(env.DB.jobs.get("leased_r02").state,"succeeded");
});
test("completion policy revision race is denied atomically",async()=>{
  const env=await policyEnv();
  await gateway.fetch(req("/v1/jobs","POST",job("leased_r03"),TOKEN),env);
  assert.equal((await gateway.fetch(req("/v1/device/claim?device=office_pc","GET",null,DEVICE),env)).status,200);
  const oldPrepare=env.DB.prepare.bind(env.DB);
  env.DB.prepare=(sql)=>{
    const prepared=oldPrepare(sql);
    if (!sql.startsWith("SELECT capability,operation,device FROM jobs")) return prepared;
    return {bind(...args){
      const stmt=prepared.bind(...args);
      return {async first(){
        const lease=await stmt.first();
        env.DB.policyState.revision+=1; // isolate concurrent signed policy update
        return lease;
      }};
    }};
  };
  const done={job_id:"leased_r03",state:"succeeded",result:{}};
  const reply=await gateway.fetch(req("/v1/device/complete","POST",done,DEVICE,"office_pc"),env);
  assert.equal(reply.status,409);
  assert.equal(env.DB.jobs.get("leased_r03").state,"leased");
});

test("submission refuses an owner policy revision race",async()=>{
  const env=await policyEnv();
  const prepare=env.DB.prepare.bind(env.DB);
  env.DB.prepare=sql=>{
    const result=prepare(sql);
    if (!sql.startsWith("INSERT INTO jobs")) return result;
    return {bind(...args){
      const statement=result.bind(...args);
      return {async first(){
        env.DB.policyState.revision+=1; // revoke concurrently before atomic insert
        return statement.first();
      }};
    }};
  };
  const r=await gateway.fetch(req("/v1/jobs","POST",job("race_post_1"),TOKEN),env);
  assert.equal(r.status,409);
  assert.equal((await r.json()).error,"policy_changed_during_submission");
  assert.equal(env.DB.jobs.has("race_post_1"),false);
});
test("claim refuses an owner policy revision race without leasing job",async()=>{
  const env=await policyEnv();
  assert.equal((await gateway.fetch(req("/v1/jobs","POST",job("race_claim_1"),TOKEN),env)).status,202);
  const prepare=env.DB.prepare.bind(env.DB);
  env.DB.prepare=sql=>{
    const result=prepare(sql);
    if (!sql.startsWith("UPDATE jobs SET state='leased'")) return result;
    return {bind(...args){
      const statement=result.bind(...args);
      return {async first(){
        env.DB.policyState.revision+=1;
        return statement.first();
      }};
    }};
  };
  const response=await gateway.fetch(req("/v1/device/claim?device=office_pc",
    "GET",null,DEVICE),env);
  assert.equal(response.status,409);
  assert.equal((await response.json()).error,"policy_changed_during_claim");
  assert.equal(env.DB.jobs.get("race_claim_1").state,"queued");
});
test("unchanged signed grants avoid repeated D1 row writes",async()=>{
  const env=await policyEnv();
  assert.equal(env.DB.policyRevisionWrites,0);
  assert.equal((await gateway.fetch(req("/v1/jobs","POST",job("reads_001"),TOKEN),env)).status,202);
  assert.equal(env.DB.policyRevisionWrites,1);
  assert.equal((await gateway.fetch(req("/v1/jobs","POST",job("reads_002"),TOKEN),env)).status,202);
  assert.equal(env.DB.policyRevisionWrites,1);
  assert.equal((await gateway.fetch(req("/v1/device/claim?device=office_pc","GET",null,DEVICE),env)).status,200);
  assert.equal(env.DB.policyRevisionWrites,1);
  await signRotatedPolicy(env,2,false);
  assert.equal((await gateway.fetch(req("/v1/jobs","POST",job("reads_003"),TOKEN),env)).status,403);
  assert.equal(env.DB.policyRevisionWrites,2);
  assert.equal((await gateway.fetch(req("/v1/jobs","POST",job("reads_004"),TOKEN),env)).status,403);
  assert.equal(env.DB.policyRevisionWrites,2);
});

test("unauthenticated requests do not touch owner policy or D1",async()=>{
  const env=await policyEnv();
  // Even when the policy storage fails, invalid credentials cannot trigger it.
  env.DB.prepare=()=>{throw Error("D1 access denied for unauthorized requests")};
  for (const [path,method,body,token,device,expected] of [
    ["/v1/jobs","POST",job("bad_auth_01"),null,null,401],
    ["/v1/jobs","POST",job("bad_auth_02"),"wrong-token",null,401],
    ["/v1/device/claim?device=office_pc","GET",null,"wrong-token",null,401],
    ["/v1/device/complete","POST",{job_id:"bad_auth_03",state:"failed",result:{}},
      "wrong-token","office_pc",401],
    ["/v1/something-else","POST",{},TOKEN,null,404],
    ["/v1/device/claim?device=%%%","GET",null,DEVICE,null,400]
  ]) {
    const reply=await gateway.fetch(req(path,method,body,token,device),env);
    assert.equal(reply.status,expected,path+" must reject before D1");
  }
  assert.equal(env.DB.policyRevisionWrites,0);
});
test("unknown path and bad token bypass expensive signed-policy parsing",async()=>{
  const env=await policyEnv();
  Object.defineProperty(env,"OWNER_POLICY_JSON",{
    get(){throw Error("No policy read permitted for unauthenticated requests")}
  });
  assert.equal((await gateway.fetch(req("/v1/jobs","POST",job("bad_auth_04")),env)).status,401);
  assert.equal((await gateway.fetch(req("/v1/enable","POST",{},TOKEN),env)).status,404);
});
test("valid identity without owner policy still fails closed",async()=>{
  const env=await policyEnv();
  delete env.OWNER_POLICY_SIGNATURE_B64;
  assert.equal((await gateway.fetch(req("/v1/jobs","POST",job("missing_01"),TOKEN),env)).status,503);
  assert.equal((await gateway.fetch(req("/v1/device/claim?device=office_pc","GET",null,DEVICE),env)).status,503);
});
