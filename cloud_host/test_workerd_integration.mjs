// Isolated signed-policy integration test using actual local workerd + D1.
// Ephemeral synthetic credentials only; never contacts a Cloudflare account.
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const wrangler=resolve("node_modules/.bin/wrangler");
const config="cloud_host/wrangler.lab.toml";
const persistence=mkdtempSync(join(tmpdir(),"uag-workerd-lab-"));
const SUBMIT="synthetic-submit-token-only-xxxxxxxxxxxxxx-12345";
const DEVICE="synthetic-device-token-only-xxxxxxxxxxxxxx-12345";
const keyPair=await webcrypto.subtle.generateKey("Ed25519",true,["sign","verify"]);
const pub=Buffer.from(await webcrypto.subtle.exportKey("raw",keyPair.publicKey)).toString("base64");
const b64=x=>Buffer.from(x).toString("base64");
let processNumber=0;

function waitProcess(child,timeout=12000){
  return new Promise((res,rej)=>{
    let settled=false;
    const timer=setTimeout(()=>{if(!settled){settled=true;child.kill("SIGKILL");rej(Error("command timeout"));}},timeout);
    child.once("error",e=>{if(!settled){settled=true;clearTimeout(timer);rej(e)}});
    child.once("exit",code=>{if(!settled){settled=true;clearTimeout(timer);res(code)}});
  });
}
async function command(args) {
  const child=spawn(wrangler,args,{stdio:["ignore","pipe","pipe"],
    env:{...process.env,WRANGLER_SEND_METRICS:"false"}});
  let output="";
  child.stdout.on("data",x=>output+=String(x).slice(0,3000));
  child.stderr.on("data",x=>output+=String(x).slice(0,3000));
  const code=await waitProcess(child,20000);
  assert.equal(code,0,"local D1 init failed: "+output.slice(-600));
}
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
async function signedPolicy(revision, enabled){
  const policy=JSON.stringify({version:1,owner:"local_owner",revision,
    expires_utc:"2099-01-01T00:00:00Z",
    capabilities:{windows_diagnostics:{enabled,operations:["snapshot"],devices:["office_pc"]}}});
  const sig=await webcrypto.subtle.sign("Ed25519",keyPair.privateKey,new TextEncoder().encode(policy));
  return {policy,sig:b64(sig)};
}
async function launch(p){
  const port=17900+(++processNumber);
  const flags=[
    "--var","OWNER_PUBLIC_KEY_B64:"+pub,
    "--var","OWNER_POLICY_JSON:"+p.policy,
    "--var","OWNER_POLICY_SIGNATURE_B64:"+p.sig,
    "--var","SUBMIT_TOKEN:"+SUBMIT,
    "--var","DEVICE_TOKENS_JSON:"+JSON.stringify({office_pc:DEVICE})
  ];
  const child=spawn(wrangler,["dev","--local","--ip","127.0.0.1",
    "--port",String(port),"--config",config,"--persist-to",persistence,...flags],
    {stdio:["ignore","pipe","pipe"],env:{...process.env,WRANGLER_SEND_METRICS:"false"}});
  let diagnostic="";
  child.stdout.on("data",x=>diagnostic=(diagnostic+String(x)).slice(-1500));
  child.stderr.on("data",x=>diagnostic=(diagnostic+String(x)).slice(-1500));
  const base="http://127.0.0.1:"+port;
  let ready=false;
  for(let i=0;i<45;i++){
    if(child.exitCode!==null)break;
    try {
      const res=await fetch(base+"/health",{signal:AbortSignal.timeout(750)});
      if(res.status===200) {ready=true;break;}
    }catch{}
    await sleep(300);
  }
  if(!ready){child.kill("SIGTERM");throw Error("local workerd startup failed: "+diagnostic.slice(-1000));}
  return {child,base};
}
async function stop(proc){
  if(!proc || proc.child.exitCode!==null)return;
  const c=proc.child;
  c.kill("SIGTERM");
  await Promise.race([
    new Promise(r=>c.once("exit",r)),
    sleep(4500).then(()=>{if(c.exitCode===null)c.kill("SIGKILL")})
  ]);
}
async function submit(proc,id){
  const resp=await fetch(proc.base+"/v1/jobs",{method:"POST",
    headers:{"content-type":"application/json","authorization":"Bearer "+SUBMIT},
    body:JSON.stringify({job_id:id,capability:"windows_diagnostics",
      operation:"snapshot",device:"office_pc",payload:{}})});
  return resp.status;
}
let live=null;
try{
  await command(["d1","execute","DB","--local","--config",config,
    "--persist-to",persistence,"--file","cloud_host/schema.sql","--yes"]);
  const old=await signedPolicy(1,true);
  live=await launch(old);
  assert.equal(await submit(live,"lab_initial_001"),202,"Initial signed grant failed");
  // Real workerd HTTP route, not just a mocked gateway unit test.
  const rejected=await fetch(live.base+"/v1/jobs",{
    method:"POST",
    headers:{"authorization":"Bearer invalid-public-test-token"},
    body:JSON.stringify({job_id:"not_authorized",payload:{}})
  });
  assert.equal(rejected.status,401,"Invalid token must fail before owner policy checks");
  const unsupported=await fetch(live.base+"/v1/enable",{
    method:"POST",headers:{"authorization":"Bearer "+SUBMIT},body:"{}"
  });
  assert.equal(unsupported.status,404,"Remote enable endpoint must not exist");
  const claim=await fetch(live.base+"/v1/device/claim?device=office_pc",{
    headers:{authorization:"Bearer "+DEVICE}
  });
  assert.equal(claim.status,200,"Synthetic device failed to lease job");
  assert.equal((await claim.json()).job_id,"lab_initial_001");
  await stop(live); live=null;

  const revoked=await signedPolicy(2,false);
  live=await launch(revoked);
  assert.equal(await submit(live,"lab_revoked_002"),403,"Revocation not enforced");
  const complete=()=>fetch(live.base+"/v1/device/complete",{method:"POST",
    headers:{"content-type":"application/json","authorization":"Bearer "+DEVICE,
      "x-device-id":"office_pc"},
    body:JSON.stringify({job_id:"lab_initial_001",state:"succeeded",
      result:{ram_used_percent:80}})
  });
  const revokedCompletion=await complete();
  assert.equal(revokedCompletion.status,403,
    "Previously leased job must not complete after owner revocation");
  assert.equal((await revokedCompletion.json()).error,"grant_revoked_after_lease");
  assert.equal((await complete()).status,409,
    "Revoked leased job was not quarantined");
  await stop(live); live=null;

  live=await launch(old);
  assert.equal(await submit(live,"lab_replayed_003"),503,"Stale signed grant accepted");
  await stop(live); live=null;

  const mutated=await signedPolicy(2,true);
  live=await launch(mutated);
  assert.equal(await submit(live,"lab_mutated_004"),503,"Same-revision substitution accepted");
  await stop(live); live=null;
  console.log("WORKERD_REAL_D1_SIGNED_REVOCATION_ROLLBACK_PASSED");
  console.log("WORKERD_REAL_D1_LEASED_COMPLETION_REVOCATION_PASSED");
  console.log("WORKERD_UNAUTHORIZED_PREFLIGHT_DENIED_PASSED");
}finally{
  await stop(live);
  rmSync(persistence,{recursive:true,force:true});
}
