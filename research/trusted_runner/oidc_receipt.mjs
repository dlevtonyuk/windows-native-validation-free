// RESEARCH ONLY: verify a GitHub-issued OIDC identity token attesting a
// privacy-safe aggregate report. NEVER accept this token as authorization for
// payroll, Workyard edits, cloud deployment or other business effects.
// A production verifier must obtain GitHub's authentic JWKS securely and
// pin the expected PRIVATE repository ID and exact workflow SHA out of band.
import {createHash,createPublicKey,verify as rsaVerify} from 'node:crypto';
const MAX_JWT=12000, SHA=/^[0-9a-f]{64}$/, HASH40=/^[0-9a-f]{40}$/;
function denied(code){const e=new Error(code);e.code=code;throw e}
function decode(part){
 if(typeof part!=='string'||!/^[-_A-Za-z0-9]+$/.test(part)||part.length>10000)denied('oidc_encoding_invalid');
 return Buffer.from(part.replace(/-/g,'+').replace(/_/g,'/'),'base64');
}
function canonical(x){
 if(x===null)return 'null';
 if(typeof x==='string'||typeof x==='boolean')return JSON.stringify(x);
 if(typeof x==='number'){if(!Number.isSafeInteger(x))denied('unsafe_report_number');return JSON.stringify(x)}
 if(Array.isArray(x))return '['+x.map(canonical).join(',')+']';
 if(typeof x==='object'&&x!==null){
  const keys=Object.keys(x).sort();
  if(keys.length>25)denied('report_too_many_fields');
  return '{'+keys.map(k=>JSON.stringify(k)+':'+canonical(x[k])).join(',')+'}';
 }
 denied('invalid_report_type');
}
export function reportDigest(report){
 if(!report||typeof report!=='object'||Array.isArray(report)||
   Object.keys(report).sort().join(',')!==
   'capability_count,cron_receipts,enabled_capabilities,execution,held_job_count,kind,latest_cron_slot_ms,owner_only_activation_status')
   denied('report_fields_invalid');
 if(report.kind!=='owner_runner_foundation_read_probe'||report.execution!=='NONE'||
    report.enabled_capabilities!==0||report.owner_only_activation_status!=='NOT_PROVISIONED'||
    report.capability_count!==4||!Number.isSafeInteger(report.held_job_count)||report.held_job_count<0||
    !Number.isSafeInteger(report.cron_receipts)||report.cron_receipts<0||
    !(report.latest_cron_slot_ms===null||
      Number.isSafeInteger(report.latest_cron_slot_ms)&&report.latest_cron_slot_ms>0))
   denied('report_scope_invalid');
 const bytes=canonical(report);
 if(Buffer.byteLength(bytes)>2048)denied('report_oversized');
 return createHash('sha256').update(bytes).digest('hex');
}
export function receiptAudience(report){return 'uag-foundation-read:v1:sha256:'+reportDigest(report)}
export function verifyGithubOidcReceipt({jwt,report,jwks,expected,receivedAtMs,seenJti}){
 if(typeof jwt!=='string'||jwt.length>MAX_JWT)denied('jwt_invalid');
 if(!expected||!/^\d{1,20}$/.test(String(expected.repositoryId))||
    typeof expected.workflowRef!=='string'||
    !HASH40.test(expected.workflowSha||'')||
    !Number.isSafeInteger(receivedAtMs)||receivedAtMs<=0)denied('trusted_identity_pin_missing');
 const parts=jwt.split('.');
 if(parts.length!==3)denied('jwt_invalid');
 let header,claim;
 try{header=JSON.parse(decode(parts[0]));claim=JSON.parse(decode(parts[1]));}
 catch{denied('jwt_decode_failed')}
 if(header.alg!=='RS256'||typeof header.kid!=='string'||header.kid.length<5||
    header.typ!=='JWT')denied('jwt_header_untrusted');
 const keys=jwks?.keys;
 if(!Array.isArray(keys)||keys.length>50)denied('jwks_untrusted');
 const candidates=keys.filter(k=>k.kid===header.kid&&k.kty==='RSA'&&k.use==='sig'&&k.alg==='RS256');
 if(candidates.length!==1)denied('jwks_key_not_unique');
 const now=Math.floor(receivedAtMs/1000);
 if(claim.iss!=='https://token.actions.githubusercontent.com'||
    claim.aud!==receiptAudience(report)||
    String(claim.repository_id)!==String(expected.repositoryId)||
    claim.repository_visibility!=='private'||
    claim.workflow_ref!==expected.workflowRef||
    claim.workflow_sha!==expected.workflowSha||
    claim.ref!=='refs/heads/main'||
    claim.runner_environment!=='github-hosted')denied('oidc_identity_or_audience_mismatch');
 if(!Number.isSafeInteger(claim.iat)||!Number.isSafeInteger(claim.nbf)||!Number.isSafeInteger(claim.exp)||
    claim.iat>now+60||claim.nbf>now+60||claim.exp<now||
    claim.exp<=claim.iat||claim.exp-claim.iat>900||now-claim.iat>900)
    denied('oidc_temporal_invalid');
 if(typeof claim.jti!=='string'||claim.jti.length<6||claim.jti.length>200)denied('oidc_jti_invalid');
 let verified=false;
 try{verified=rsaVerify('RSA-SHA256',Buffer.from(parts[0]+'.'+parts[1]),createPublicKey({key:candidates[0],format:'jwk'}),decode(parts[2]));}
 catch{denied('oidc_signature_invalid')}
 if(!verified)denied('oidc_signature_invalid');
 // A seen-JTI tracker prevents repeat acceptance only where the tracker is
 // owner-independent; an assistant-editable D1 ledger is NOT a trusted replay gate.
 if(seenJti?.has?.(claim.jti))denied('oidc_replay_detected');
 return Object.freeze({valid:true,kind:'fresh_github_oidc_attestation',
    report_sha256:reportDigest(report),repository_id:String(claim.repository_id),
    workflow_sha:claim.workflow_sha,jti:claim.jti,run_id:String(claim.run_id||''),
    expires_unix:claim.exp,effect_authority:'NONE'});
}
