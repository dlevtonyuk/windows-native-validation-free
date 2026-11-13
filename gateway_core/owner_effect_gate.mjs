// RESEARCH ONLY. Trusted-device/adapter-side owner authorization fence.
// No network, no desktop interaction, no secret keys, no business adapters.
// An assistant-editable installation is NOT owner-independent security.
import {createHash,createPublicKey,verify,timingSafeEqual} from 'node:crypto';
const PREFIX=Buffer.from('302a300506032b6570032100','hex');
const B64=/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const ID=/^[a-z][a-z0-9_-]{2,63}$/;
const JOB=/^[0-9a-f]{32}$/;
const HASH=/^[0-9a-f]{64}$/;
const KEYS='capability,device_id,expires_utc,gateway_id,issued_utc,max_claims,operation,owner,payload_sha256,revision,version';
const ENVELOPE_KEYS='grant_json,signature_b64';
const MAX_LIFETIME_MS=30*24*60*60*1000;
function exact(x,keys) {
  if(!x||typeof x!=='object'||Array.isArray(x)||Object.keys(x).sort().join(',')!==keys)
    throw Error('unexpected_fields');
}
function decode(s,expected) {
  if(typeof s!=='string'||s.length>1024||!B64.test(s))throw Error('malformed_base64');
  const b=Buffer.from(s,'base64');
  if(b.length!==expected||b.toString('base64')!==s)throw Error('malformed_base64');
  return b;
}
function digest(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
function strictDate(s) {
  if(typeof s!=='string'||!/^(?:\d{4})-(?:\d{2})-(?:\d{2})T(?:\d{2}):(?:\d{2}):(?:\d{2})(?:\.\d{3})?Z$/.test(s))
    throw Error('invalid_lease_date');
  const n=Date.parse(s);
  if(!Number.isFinite(n)||new Date(n).toISOString()!==s)throw Error('invalid_lease_date');
  return n;
}
function ctHashEqual(a,b) {
  if(typeof a!=='string'||typeof b!=='string'||!HASH.test(a)||!HASH.test(b))return false;
  return timingSafeEqual(Buffer.from(a,'hex'),Buffer.from(b,'hex'));
}
// Caller must supply these values from a trusted host configuration, never
// from the untrusted remote request or assistant-controlled transport.
export function verifyOwnerEffectGrant(envelope, context) {
  if(!context||typeof context!=='object'||Array.isArray(context))throw Error('trusted_context_missing');
  exact(envelope,ENVELOPE_KEYS);
  if(typeof envelope.grant_json!=='string'||Buffer.byteLength(envelope.grant_json)>4096)
    throw Error('grant_too_large');
  const now=context.nowMs??Date.now();
  if(!Number.isSafeInteger(now)||now<=0)throw Error('invalid_trusted_clock');
  const m=JSON.parse(envelope.grant_json);
  exact(m,KEYS);
  if(m.version!==1||m.owner!=='local_owner')throw Error('invalid_grant_identity');
  if(![m.gateway_id,m.device_id,m.capability,m.operation].every(v=>typeof v==='string'&&ID.test(v)))
    throw Error('invalid_grant_scope');
  if(![context.gatewayId,context.deviceId,context.capability,context.operation].every(v=>typeof v==='string'&&ID.test(v))||
      m.gateway_id!==context.gatewayId||m.device_id!==context.deviceId||
      m.capability!==context.capability||m.operation!==context.operation)
    throw Error('grant_scope_mismatch');
  if(!Number.isSafeInteger(m.revision)||m.revision<1||!Number.isSafeInteger(context.activeRevision)||m.revision!==context.activeRevision)
    throw Error('stale_or_unactivated_revision');
  if(!Number.isSafeInteger(m.max_claims)||m.max_claims<1||m.max_claims>10000)
    throw Error('invalid_claim_budget');
  if(typeof m.payload_sha256!=='string'||!HASH.test(m.payload_sha256))
    throw Error('invalid_payload_pin');
  const issued=strictDate(m.issued_utc), expires=strictDate(m.expires_utc);
  if(issued>now+120000||expires<=now||expires<=issued||expires-issued>MAX_LIFETIME_MS||now-issued>MAX_LIFETIME_MS)
    throw Error('grant_expired_or_invalid_clock');
  const key=decode(context.pinnedOwnerPublicKeyB64,32);
  const signature=decode(envelope.signature_b64,64);
  const publicKey=createPublicKey({key:Buffer.concat([PREFIX,key]),format:'der',type:'spki'});
  if(!verify(null,Buffer.from(envelope.grant_json,'utf8'),publicKey,signature))
    throw Error('owner_signature_invalid');
  return Object.freeze({
    gateway_id:m.gateway_id,device_id:m.device_id,capability:m.capability,
    operation:m.operation,revision:m.revision,max_claims:m.max_claims,
    payload_sha256:m.payload_sha256,expires_ms:expires,grant_sha256:digest(Buffer.from(envelope.grant_json,'utf8'))
  });
}
// This function MUST execute inside the trusted adapter host, which alone
// controls its SQLite ledger and pre-registered handler. No request may inject
// a handler, a ledger path, or a signing key. Reserving consumes the job id
// even if the handler crashes: ambiguous effects are never auto-replayed.
async function executeAuthorizedEffect({grant,jobId,payloadBytes,store,handler,nowMs=Date.now()}) {
  if(!grant||typeof grant!=='object'||!JOB.test(jobId??''))throw Error('invalid_job');
  if(!Number.isSafeInteger(nowMs)||nowMs<=0||nowMs>=grant.expires_ms)
    throw Error('grant_expired');
  if(!Buffer.isBuffer(payloadBytes)&&!(payloadBytes instanceof Uint8Array))
    throw Error('invalid_payload');
  if(payloadBytes.byteLength>4096||!ctHashEqual(digest(payloadBytes),grant.payload_sha256))
    throw Error('effect_payload_not_authorized');
  if(!store||typeof store.reserve!=='function'||typeof store.finalize!=='function'||typeof handler!=='function')
    throw Error('trusted_host_missing');
  const reservation=await store.reserve({
    job_id:jobId,grant_sha256:grant.grant_sha256,revision:grant.revision,
    max_claims:grant.max_claims,payload_sha256:grant.payload_sha256
  });
  if(!reservation||reservation.state!=='reserved'||reservation.job_id!==jobId)
    throw Error('claim_not_reserved');
  let result;
  try {
    result=await handler(Buffer.from(payloadBytes));
  } catch(err) {
    // No automatic retry. If finalize fails, the reserved claim remains consumed.
    await store.finalize({job_id:jobId,outcome:'failed'});
    throw err;
  }
  await store.finalize({job_id:jobId,outcome:'succeeded'});
  return result;
}

// The ONLY public adapter execution API. Never accept an unchecked grant object
// from the transport. The owner key and active revision come from trusted host
// configuration, and the trusted store independently checks active revision.
export async function executeOwnerApprovedEffect({envelope,context,jobId,payloadBytes,store,handler,nowMs=Date.now()}) {
  if(!context||typeof context!=='object'||Array.isArray(context))throw Error('trusted_context_missing');
  const grant=verifyOwnerEffectGrant(envelope,{...context,nowMs});
  return executeAuthorizedEffect({grant,jobId,payloadBytes,store,handler,nowMs});
}
