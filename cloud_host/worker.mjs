// Cloudflare Workers Free + D1 control-plane prototype. Generic/NO SECRETS.
// No endpoints exist until OWNER_PUBLIC_KEY_B64, OWNER_POLICY_JSON,
// OWNER_POLICY_SIGNATURE_B64, SUBMIT_TOKEN, DEVICE_TOKENS_JSON and DB are
// provisioned by the actual owner. Never deploy with test keys or real data.
const idPattern = /^[a-z][a-z0-9_-]{2,63}$/;
const maxBody = 4096;
const response = (code, body) => new Response(JSON.stringify(body), {
  status: code, headers: {"content-type":"application/json","cache-control":"no-store",
    "x-content-type-options":"nosniff"}
});
const base64Bytes = str => Uint8Array.from(atob(str), c=>c.charCodeAt(0));
const encoded = str => new TextEncoder().encode(str);
const validId = s => typeof s === "string" && idPattern.test(s);

async function tokenMatches(provided, correct) {
  if (typeof correct !== "string" || correct.length < 32 || typeof provided !== "string")
    return false;
  const [a,b] = await Promise.all([crypto.subtle.digest("SHA-256", encoded(provided)),
                                    crypto.subtle.digest("SHA-256", encoded(correct))]);
  const left=new Uint8Array(a), right=new Uint8Array(b);
  let diff=0;
  for (let i=0;i<left.length;i++) diff|=left[i]^right[i];
  return diff===0;
}
async function parseBody(request) {
  const len=Number(request.headers.get("content-length") || 0);
  if (len > maxBody) throw new Error("body_too_large");
  const raw=await request.text();
  if (raw.length>maxBody) throw new Error("body_too_large");
  const result=JSON.parse(raw);
  if (!result || typeof result!=="object" || Array.isArray(result))
    throw new Error("invalid_json_object");
  return result;
}
async function ownerPolicy(env) {
  if (!env.DB || !env.OWNER_PUBLIC_KEY_B64 || !env.OWNER_POLICY_JSON
      || !env.OWNER_POLICY_SIGNATURE_B64) return null;
  try {
    const key=await crypto.subtle.importKey("raw",base64Bytes(env.OWNER_PUBLIC_KEY_B64),
      {name:"Ed25519"},false,["verify"]);
    const authentic=await crypto.subtle.verify(
      {name:"Ed25519"},key,base64Bytes(env.OWNER_POLICY_SIGNATURE_B64),
      encoded(env.OWNER_POLICY_JSON));
    if (!authentic) return null;
    const document=JSON.parse(env.OWNER_POLICY_JSON);
    if (Object.keys(document).sort().join(",") !==
        "capabilities,expires_utc,owner,revision,version" || document.version!==1 ||
        document.owner!=="local_owner" ||
        !Number.isSafeInteger(document.revision) || document.revision<1 ||
        !Number.isFinite(Date.parse(document.expires_utc)) ||
        Date.parse(document.expires_utc)<=Date.now() ||
        !document.capabilities || typeof document.capabilities!=="object") return null;
    for (const [name,p] of Object.entries(document.capabilities)){
      if (!validId(name) || !p || typeof p.enabled!=="boolean" ||
          !Array.isArray(p.operations) || !Array.isArray(p.devices) ||
          p.operations.length>64 || p.devices.length>64 ||
          !p.operations.every(validId) || !p.devices.every(validId)) return null;
    }
    // Owner-signed policies are pinned to a monotonic D1 high watermark.
    // Same revision with different signed bytes or older revision is rejected.
    // Missing DB/table fails closed; never treat a previously signed grant as current.
    const hash=[...new Uint8Array(await crypto.subtle.digest(
      "SHA-256",encoded(env.OWNER_POLICY_JSON)))].map(
        x=>x.toString(16).padStart(2,"0")).join("");
    const state=await env.DB.prepare(
      "INSERT INTO owner_policy_state (id,highest_revision,payload_sha256) VALUES (1,?,?) "+
      "ON CONFLICT(id) DO UPDATE SET "+
      "highest_revision=excluded.highest_revision,payload_sha256=excluded.payload_sha256 "+
      "WHERE excluded.highest_revision > owner_policy_state.highest_revision OR "+
      "(excluded.highest_revision = owner_policy_state.highest_revision AND "+
      "excluded.payload_sha256 = owner_policy_state.payload_sha256) "+
      "RETURNING highest_revision"
    ).bind(document.revision,hash).first();
    if (!state || state.highest_revision!==document.revision) return null;
    return {capabilities:document.capabilities,revision:document.revision,hash};
  }catch {return null;}
}
function permitted(caps,cap,op,device) {
  if (![cap,op,device].every(validId)) return false;
  const rule=caps[cap];
  return !!(rule && rule.enabled===true &&
    rule.operations.includes(op) && rule.devices.includes(device));
}
async function auth(request, token) {
  const header=request.headers.get("authorization") || "";
  if (!header.startsWith("Bearer ")) return false;
  return tokenMatches(header.slice(7),token);
}

export default {
  async fetch(request,env) {
    const url=new URL(request.url);
    if (url.pathname==="/health" && request.method==="GET")
      return response(200,{service:"universal-gateway",status:"no_public_capabilities"});
    // Fail closed if owner has not configured an authenticated, signed policy.
    const policy=await ownerPolicy(env);
    if (!policy) return response(503,{error:"owner_activation_not_configured"});
    const {capabilities:caps,revision,hash}=policy;
    try {
      if (url.pathname==="/v1/jobs" && request.method==="POST") {
        if (!await auth(request,env.SUBMIT_TOKEN))
          return response(401,{error:"unauthorized"});
        const job=await parseBody(request);
        if (Object.keys(job).sort().join(",")!=="capability,device,job_id,operation,payload" ||
          ![job.job_id,job.capability,job.operation,job.device].every(validId) ||
          !job.payload || typeof job.payload!=="object" ||
          Array.isArray(job.payload) || JSON.stringify(job.payload).length>1024)
          return response(400,{error:"invalid_job"});
        if (!permitted(caps,job.capability,job.operation,job.device))
          return response(403,{error:"capability_disabled_or_out_of_scope"});
        // Submit only while this exact signed revision remains current in D1.
        // An owner revocation racing this request cannot create an old-policy job.
        try {
          const inserted=await env.DB.prepare(
            "INSERT INTO jobs(job_id,capability,operation,device,payload_json,state,created_at) "+
            "SELECT ?,?,?,?,?,'queued',? WHERE EXISTS "+
            "(SELECT 1 FROM owner_policy_state WHERE id=1 AND highest_revision=? "+
            "AND payload_sha256=?) RETURNING job_id"
          ).bind(job.job_id,job.capability,job.operation,job.device,
                 JSON.stringify(job.payload),Date.now(),revision,hash).first();
          if (!inserted) return response(409,{error:"policy_changed_during_submission"});
        }catch {return response(409,{error:"duplicate_job_or_storage_unavailable"});}
        return response(202,{job_id:job.job_id,state:"queued"});
      }
      if (url.pathname==="/v1/device/claim" && request.method==="GET") {
        const device=url.searchParams.get("device");
        if (!validId(device)) return response(400,{error:"invalid_device"});
        let tokens;
        try {tokens=JSON.parse(env.DEVICE_TOKENS_JSON);}catch {return response(503,{error:"device_tokens_unconfigured"});}
        if (!await auth(request,tokens?.[device])) return response(401,{error:"unauthorized"});
        // An expired lease is quarantined, NEVER blindly replayed. Owners can
        // reconcile interrupted side effects before explicitly resubmitting.
        await env.DB.prepare(
          "UPDATE jobs SET state='interrupted' WHERE state='leased' AND lease_until<? AND device=?"
        ).bind(Date.now(),device).run();
        // A single atomic claim, without issuing arbitrary local commands.
        // Subsequent adapter must independently verify operation/owner grant.
        const row=await env.DB.prepare(
          "UPDATE jobs SET state='leased',lease_until=? WHERE job_id="+
          "(SELECT job_id FROM jobs WHERE state='queued' AND device=? "+
          "ORDER BY created_at LIMIT 1) AND EXISTS "+
          "(SELECT 1 FROM owner_policy_state WHERE id=1 AND highest_revision=? "+
          "AND payload_sha256=?) RETURNING job_id,capability,operation,device,payload_json"
        ).bind(Date.now()+30000,device,revision,hash).first();
        if (!row) {
          const current=await env.DB.prepare(
            "SELECT 1 AS matched FROM owner_policy_state WHERE id=1 AND "+
            "highest_revision=? AND payload_sha256=?"
          ).bind(revision,hash).first();
          return current?response(200,{state:"empty"}):
            response(409,{error:"policy_changed_during_claim"});
        }
        if (!permitted(caps,row.capability,row.operation,row.device)){
          await env.DB.prepare(
            "UPDATE jobs SET state='interrupted' WHERE job_id=? AND state='leased'"
          ).bind(row.job_id).run();
          return response(403,{error:"grant_revoked_after_queue"});
        }
        return response(200,{state:"leased",job_id:row.job_id,capability:row.capability,
          operation:row.operation,device:row.device,payload:JSON.parse(row.payload_json)});
      }
      if (url.pathname==="/v1/device/complete" && request.method==="POST") {
        const device=request.headers.get("x-device-id");
        let tokens;
        try {tokens=JSON.parse(env.DEVICE_TOKENS_JSON);}catch {return response(503,{error:"device_tokens_unconfigured"});}
        if (!validId(device) || !await auth(request,tokens?.[device]))
          return response(401,{error:"unauthorized"});
        const data=await parseBody(request);
        if (!validId(data.job_id) || !["succeeded","failed"].includes(data.state) ||
            typeof data.result!=="object" || !data.result ||
            JSON.stringify(data.result).length>1024)
          return response(400,{error:"invalid_completion"});
        // Completion is NOT authorization for an already leased operation:
        // recheck the current owner grant and match the policy revision in
        // the SAME D1 statement that records a job's completion.
        const lease=await env.DB.prepare(
          "SELECT capability,operation,device FROM jobs WHERE job_id=? AND device=? AND state='leased' AND lease_until>?"
        ).bind(data.job_id,device,Date.now()).first();
        if (!lease) return response(409,{error:"not_leased_or_lease_expired"});
        const guard=" AND EXISTS (SELECT 1 FROM owner_policy_state WHERE id=1 "+
          "AND highest_revision=? AND payload_sha256=?) RETURNING job_id";
        if (!permitted(caps,lease.capability,lease.operation,lease.device)) {
          // Never silently relabel a side effect already in flight as undone.
          // Quarantine for owner reconciliation; do not auto-replay it.
          const interrupted=await env.DB.prepare(
            "UPDATE jobs SET state='interrupted' WHERE job_id=? AND device=? "+
            "AND state='leased' AND lease_until>?"+guard
          ).bind(data.job_id,device,Date.now(),revision,hash).first();
          return interrupted?response(403,{error:"grant_revoked_after_lease"}):
            response(409,{error:"lease_or_policy_changed"});
        }
        const row=await env.DB.prepare(
          "UPDATE jobs SET state=?,result_json=? WHERE job_id=? AND device=? "+
          "AND state='leased' AND lease_until>?"+guard
        ).bind(data.state,JSON.stringify(data.result),data.job_id,device,
               Date.now(),revision,hash).first();
        return row?response(200,{job_id:data.job_id,state:data.state}):
          response(409,{error:"lease_or_policy_changed"});
      }
      return response(404,{error:"unsupported_operation"});
    }catch (e){
      if (e?.message==="body_too_large" || e?.message==="invalid_json_object" || e instanceof SyntaxError)
        return response(400,{error:"invalid_request"});
      return response(503,{error:"temporary_unavailable"});
    }
  }
};
