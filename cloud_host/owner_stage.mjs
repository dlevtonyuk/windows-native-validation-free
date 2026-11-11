/**
 * Owner-only, DISABLED-policy staging endpoint.
 * Research implementation. Never changes the live signed owner policy,
 * grants, jobs, or agent credentials. No real owner key in this repository.
 */
const reply=(status,body)=>new Response(JSON.stringify(body),{
  status,headers:{"content-type":"application/json; charset=utf-8",
    "cache-control":"no-store","x-content-type-options":"nosniff",
    "referrer-policy":"no-referrer","content-security-policy":"default-src 'none'"}
});
const base64=/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const id=/^[a-z][a-z0-9_-]{2,63}$/;
function strictBytes(s,len){
  if(typeof s!=="string"||s.length>120||!base64.test(s))throw Error("invalid_base64");
  const bytes=Uint8Array.from(atob(s),c=>c.charCodeAt(0));
  if(bytes.length!==len||btoa(String.fromCharCode(...bytes))!==s)
    throw Error("invalid_base64");
  return bytes;
}
function validateDisabledPolicy(raw,now){
  if(typeof raw!=="string"||new TextEncoder().encode(raw).byteLength>4096)
    throw Error("invalid_policy_size");
  const p=JSON.parse(raw);
  if(!p||typeof p!=="object"||Array.isArray(p)||
      Object.keys(p).sort().join(",")!=="capabilities,expires_utc,owner,revision,version"||
      p.version!==1||p.owner!=="local_owner"||
      !Number.isSafeInteger(p.revision)||p.revision<1||
      typeof p.expires_utc!=="string"||
      !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{3})?Z$/.test(p.expires_utc))
    throw Error("invalid_policy");
  const end=Date.parse(p.expires_utc);
  if(!Number.isFinite(end)||end<=now||end>now+90*86400000)
    throw Error("invalid_expiry");
  const caps=p.capabilities;
  if(!caps||typeof caps!=="object"||Array.isArray(caps)||Object.keys(caps).length>1)
    throw Error("invalid_capabilities");
  for(const [name,c] of Object.entries(caps)){
    if(name!=="synthetic_probe"||!c||typeof c!=="object"||Array.isArray(c)||
       Object.keys(c).sort().join(",")!=="devices,enabled,operations"||
       c.enabled!==false||!Array.isArray(c.devices)||!Array.isArray(c.operations)||
       c.devices.length>8||c.operations.length>8||
       !c.devices.every(x=>typeof x==="string"&&id.test(x)&&x==="cloud_runner")||
       !c.operations.every(x=>typeof x==="string"&&id.test(x)&&x==="echo")||
       new Set(c.devices).size!==c.devices.length||
       new Set(c.operations).size!==c.operations.length)
      throw Error("unsupported_capability");
  }
  return p;
}
async function boundedJSON(request){
  const maxBytes=8192;
  const header=request.headers.get("content-length");
  if(header!==null&&(!/^(0|[1-9][0-9]*)$/.test(header)||Number(header)>maxBytes))
    throw Error("invalid_length");
  if(!request.body)throw Error("missing_body");
  const reader=request.body.getReader();let n=0;const chunks=[];
  try{
    for(;;){
      const {done,value}=await reader.read();
      if(done)break;
      if(!(value instanceof Uint8Array))throw Error("invalid_body");
      n+=value.byteLength;
      if(n>maxBytes)throw Error("invalid_body");
      chunks.push(value);
    }
  }catch(e){try{await reader.cancel()}catch{};throw e}
  finally{reader.releaseLock()}
  const bytes=new Uint8Array(n);let offset=0;
  for(const part of chunks){bytes.set(part,offset);offset+=part.byteLength}
  return JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(bytes));
}
async function ownerIdentity(env,ctx){
  if(!ctx?.access||typeof ctx.access.getIdentity!=="function")return null;
  if(typeof env.OWNER_ACCESS_AUD!=="string"||!env.OWNER_ACCESS_AUD||
     ctx.access.aud!==env.OWNER_ACCESS_AUD)return null;
  const expected=env.OWNER_ACCESS_EMAIL;
  if(typeof expected!=="string"||expected.length<3||expected.length>254)return null;
  let identity;
  try{identity=await ctx.access.getIdentity()}catch{return null}
  if(typeof identity?.email!=="string")return null;
  const email=identity.email.trim().toLowerCase();
  return email===expected.trim().toLowerCase()?email:null;
}
export async function handleOwnerStage(request,env={},ctx={},options={}){
  const url=new URL(request.url);
  if(!url.pathname.startsWith("/owner/"))return null;
  if(url.pathname!=="/owner/policy/stage"||request.method!=="POST")
    return reply(404,{error:"unsupported_operation"});
  // Cloudflare ctx.access is issued only for the directly authenticated invocation.
  // A user-supplied header is not authentication.
  const actor=await ownerIdentity(env,ctx);
  if(!actor)return reply(403,{error:"owner_access_required"});
  // Defend against browser cookie-driven cross-site submission.
  if(request.headers.get("origin")!==url.origin||
     request.headers.get("sec-fetch-site")==="cross-site"||
     request.headers.get("content-type")?.split(";")[0].trim().toLowerCase()!=="application/json")
    return reply(403,{error:"same_origin_json_required"});
  if(!env.DB||typeof env.DB.prepare!=="function")
    return reply(503,{error:"staging_db_unavailable"});
  let envelope,pub,sig,policy;
  try{
    envelope=await boundedJSON(request);
    if(!envelope||typeof envelope!=="object"||Array.isArray(envelope)||
       Object.keys(envelope).sort().join(",")!=="policy_json,signature_b64")
      throw Error("invalid_envelope");
    policy=validateDisabledPolicy(envelope.policy_json,options.now??Date.now());
    pub=strictBytes(env.OWNER_PUBLIC_KEY_B64,32);
    sig=strictBytes(envelope.signature_b64,64);
    const key=await crypto.subtle.importKey("raw",pub,{name:"Ed25519"},false,["verify"]);
    const verified=await crypto.subtle.verify({name:"Ed25519"},key,sig,
      new TextEncoder().encode(envelope.policy_json));
    if(!verified)return reply(403,{error:"invalid_owner_signature"});
  }catch{return reply(400,{error:"invalid_signed_policy"})}
  try{
    const toHex=bytes=>Array.from(bytes,v=>v.toString(16).padStart(2,"0")).join("");
    const digest=toHex(new Uint8Array(await crypto.subtle.digest("SHA-256",
      new TextEncoder().encode(envelope.policy_json))));
    const actorHash=toHex(new Uint8Array(await crypto.subtle.digest("SHA-256",
      new TextEncoder().encode(actor))));
    const stmt=`INSERT INTO owner_policy_stage
      (id,revision,policy_json,signature_b64,digest_hex,actor_sha256,staged_at)
      VALUES(1,?,?,?,?,?,?)
      ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,
        policy_json=excluded.policy_json,signature_b64=excluded.signature_b64,
        digest_hex=excluded.digest_hex,actor_sha256=excluded.actor_sha256,
        staged_at=excluded.staged_at
      WHERE excluded.revision>owner_policy_stage.revision
      RETURNING revision,digest_hex`;
    const row=await env.DB.prepare(stmt).bind(policy.revision,envelope.policy_json,
      envelope.signature_b64,digest,actorHash,options.now??Date.now()).first();
    if(!row)return reply(409,{error:"stale_or_replayed_revision"});
    return reply(202,{state:"staged_disabled",revision:row.revision,
      digest_prefix:row.digest_hex.slice(0,12)});
  }catch{return reply(503,{error:"staging_write_unavailable"})}
}
