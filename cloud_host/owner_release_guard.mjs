// Research only: trusted owner verification before one-use local SQLite claim.
// Neither this source nor the SQLite DB is a security boundary when deployed
// from an assistant-editable repository. No external requests or deployments.
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {dirname,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {verifyOwnerRelease} from './owner_release_verifier.mjs';
const script=join(dirname(fileURLToPath(import.meta.url)),'owner_release_ledger.py');
function ledger(action,db,opt={}){
 if(typeof db!=='string'||db.length===0||db.length>2048)
  throw Error('invalid_ledger_path');
 const args=[script,action,'--db',db];
 if(action==='finalize')
  args.push('--claim-id',opt.claim_id,'--result',opt.result);
 const p=spawnSync(opt.pythonBin||'python',args,{
  encoding:'utf8',timeout:5000,maxBuffer:65536,
  input:action==='reserve'?JSON.stringify(opt.receipt):''
 });
 if(p.error)throw Error('trusted_ledger_execution_failed');
 if(p.status!==0||p.signal)throw Error('trusted_ledger_denied_or_unavailable');
 let data;try{data=JSON.parse(p.stdout)}
 catch{throw Error('invalid_trusted_ledger_response')}
 if(!data||typeof data!=='object'||Array.isArray(data))
  throw Error('invalid_trusted_ledger_response');
 return data;
}
export function reserveVerifiedRelease({dbPath,envelope,expected,pythonBin}){
 if(!expected||typeof expected!=='object'||typeof expected.worker!=='string')
  throw Error('missing_trusted_context');
 const state=ledger('status',dbPath,{pythonBin});
 if(!Array.isArray(state.heads))throw Error('invalid_trusted_ledger_response');
 const match=state.heads.filter(x=>x.target_worker===expected.worker);
 if(match.length>1)throw Error('invalid_trusted_ledger_response');
 const previous=match.length?match[0].highest_revision:0;
 if(!Number.isSafeInteger(previous)||previous<0)
  throw Error('invalid_trusted_ledger_response');
 const verified=verifyOwnerRelease(envelope,{...expected,previousRevision:previous});
 const authDigest=createHash('sha256').update('uag-owner-release-v1\0','utf8')
  .update(envelope.manifest_json,'utf8').update('\0','utf8')
  .update(envelope.signature_b64,'ascii').digest('hex');
 return ledger('reserve',dbPath,{pythonBin,receipt:{
  target_worker:verified.worker,repository:verified.repository,
  branch:verified.branch,source_commit:verified.commit,
  release_revision:verified.release_revision,
  artifact_sha256:verified.sha256,
  authorization_digest_sha256:authDigest
 }});
}
export function finalizeReservedRelease({dbPath,claimId,result,pythonBin}){
 if(typeof claimId!=='string'||!/^[0-9a-f]{32}$/.test(claimId))
  throw Error('invalid_claim_id');
 if(!['deployed','failed'].includes(result))throw Error('invalid_final_result');
 return ledger('finalize',dbPath,{claim_id:claimId,result,pythonBin});
}
export function readReleaseLedger({dbPath,pythonBin}){
 return ledger('status',dbPath,{pythonBin});
}
