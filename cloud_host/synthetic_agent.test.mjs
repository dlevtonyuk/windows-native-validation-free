import test from "node:test";
import assert from "node:assert/strict";
import {runSyntheticOnce} from "./synthetic_agent.mjs";

const token="synthetic-fixture-only-device-token-00000001";
const endpoint="https://gateway.example.invalid/";
const job={state:"leased",job_id:"cloud_job_001",capability:"synthetic_probe",
  operation:"echo",device:"cloud_runner",payload:{nonce:"synthetic_only_1"}};
const json=x=>new Response(JSON.stringify(x),{status:200,headers:{"content-type":"application/json"}});

test("valid synthetic job performs only in-memory echo and acknowledges exact job",async()=>{
  let calls=[];
  const fetchImpl=async(url,init)=>{
    calls.push({url,method:init.method,body:init.body});
    return calls.length===1?json(job):json({job_id:"cloud_job_001",state:"succeeded"});
  };
  const r=await runSyntheticOnce({endpoint,token,fetchImpl});
  assert.deepEqual(r,{state:"succeeded",job_id:"cloud_job_001"});
  assert.equal(calls.length,2);
  assert.ok(calls[0].url.endsWith("/v1/device/claim?device=cloud_runner"));
  assert.ok(calls[1].url.endsWith("/v1/device/complete"));
  assert.deepEqual(JSON.parse(calls[1].body),{
    job_id:"cloud_job_001",state:"succeeded",result:{kind:"synthetic_probe",nonce:"synthetic_only_1"}
  });
});
test("empty queue does not complete or run any operation",async()=>{
  let calls=0;
  const r=await runSyntheticOnce({endpoint,token,fetchImpl:async()=>{calls++;return json({state:"empty"})}});
  assert.deepEqual(r,{state:"empty"});assert.equal(calls,1);
});
test("unknown capabilities, operations and unsafe payloads are never acknowledged",async()=>{
  const cases=[
    {...job,capability:"windows_diagnostics"},
    {...job,operation:"run_shell"},
    {...job,device:"office_pc"},
    {...job,payload:{nonce:"safe",command:"whoami"}},
    {...job,payload:{nonce:"../../etc/passwd"}},
    {...job,payload:{nonce:1}},
    {...job,job_id:"../outside"},
  ];
  for(const claimed of cases){
    let calls=0;
    const r=await runSyntheticOnce({endpoint,token,fetchImpl:async()=>{calls++;return json(claimed)}});
    assert.deepEqual(r,{state:"refused_unknown_job"});
    assert.equal(calls,1,"must not complete unknown jobs");
  }
});
test("fails closed on wrong credentials or unsafe HTTP targets",async()=>{
  await assert.rejects(()=>runSyntheticOnce({endpoint,token:"short",fetchImpl:async()=>json(job)}),
    /invalid_device_credential/);
  await assert.rejects(()=>runSyntheticOnce({endpoint:"http://public.example.invalid/",token,fetchImpl:async()=>json(job)}),
    /unsafe_endpoint/);
  await assert.rejects(()=>runSyntheticOnce({endpoint:"https://user:password@example.invalid/",token,fetchImpl:async()=>json(job)}),
    /unsafe_endpoint/);
});
test("network denial or revocation never claims success",async()=>{
  const denied=await runSyntheticOnce({endpoint,token,fetchImpl:async()=>new Response("denied",{status:403})});
  assert.deepEqual(denied,{state:"unavailable",http_status:403});
  let calls=0;
  const refused=await runSyntheticOnce({endpoint,token,fetchImpl:async()=>{calls++;return calls===1?json(job):new Response("revoked",{status:409})}});
  assert.deepEqual(refused,{state:"completion_refused",http_status:409});
});
test("refuses oversized claim responses and invalid acknowledgments",async()=>{
  await assert.rejects(()=>runSyntheticOnce({endpoint,token,fetchImpl:async()=>new Response("X".repeat(4097),{status:200})}),
    /oversized_response/);
  let calls=0;
  await assert.rejects(()=>runSyntheticOnce({endpoint,token,fetchImpl:async()=>{calls++;return calls===1?json(job):json({job_id:"wrong",state:"succeeded"})}}),
    /invalid_completion_ack/);
});
