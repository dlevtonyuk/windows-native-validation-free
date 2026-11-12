import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {dirname,join as joinPath} from 'node:path';
import {fileURLToPath} from 'node:url';
import {mkdtempSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {reserveVerifiedRelease,finalizeReservedRelease,readReleaseLedger} from './owner_release_guard.mjs';

const {publicKey,privateKey}=generateKeyPairSync('ed25519'); // disposable key
const publicB64=publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64');
const now=Date.parse('2026-11-12T14:00:00.000Z');
const artifact=Buffer.from('synthetic artifact only; no cloud operations\n');
const sha=createHash('sha256').update(artifact).digest('hex');
const commit='a'.repeat(40);
const manifest=(rev=1)=>({version:1,owner:'local_owner',release_revision:rev,
 repository:'research/disposable',branch:'approved/synthetic',source_commit:commit,
 target_worker:'synthetic_worker',artifact_sha256:sha,
 issued_utc:new Date(now-1000).toISOString(),
 expires_utc:new Date(now+3600000).toISOString()});
function signManifest(m){
 const manifest_json=JSON.stringify(m);
 return {manifest_json,signature_b64:sign(null,Buffer.from(manifest_json),privateKey).toString('base64')};
}
const expected={repository:'research/disposable',branch:'approved/synthetic',
 worker:'synthetic_worker',commit,pinnedOwnerPublicKeyB64:publicB64,nowMs:now,
 artifactBytes:artifact};
function scratch(){
 const dir=mkdtempSync(join(tmpdir(),'uag-synthetic-release-'));
 const db=join(dir,'ledger.sqlite');
 const script=joinPath(dirname(fileURLToPath(import.meta.url)),'owner_release_ledger.py');
 const p=spawnSync('python',[script,'init','--db',db],{encoding:'utf8',timeout:10000});
 assert.equal(p.status,0,'Only the synthetic owner fixture explicitly initializes the ledger');
 return {db,close:()=>rmSync(dir,{force:true,recursive:true})};
}
test('valid signed source is reserved then completed once',()=>{
 const x=scratch();try{
  const c=reserveVerifiedRelease({dbPath:x.db,envelope:signManifest(manifest()),expected});
  assert.equal(c.state,'reserved');assert.equal(c.release_revision,1);
  assert.equal(finalizeReservedRelease({dbPath:x.db,claimId:c.claim_id,result:'deployed'}).state,'deployed');
  assert.throws(()=>finalizeReservedRelease({dbPath:x.db,claimId:c.claim_id,result:'deployed'}),/trusted_ledger_denied/);
  assert.throws(()=>reserveVerifiedRelease({dbPath:x.db,envelope:signManifest(manifest()),expected}),/release_scope_or_revision_invalid/);
 }finally{x.close()}
});
test('interruption and failure both consume owner approval',()=>{
 const x=scratch();try{
  reserveVerifiedRelease({dbPath:x.db,envelope:signManifest(manifest(6)),expected});
  assert.equal(readReleaseLedger({dbPath:x.db}).attempts[0].state,'reserved');
  assert.throws(()=>reserveVerifiedRelease({dbPath:x.db,envelope:signManifest(manifest(6)),expected}),/release_scope_or_revision_invalid/);
  const c=reserveVerifiedRelease({dbPath:x.db,envelope:signManifest(manifest(7)),expected});
  finalizeReservedRelease({dbPath:x.db,claimId:c.claim_id,result:'failed'});
  assert.throws(()=>reserveVerifiedRelease({dbPath:x.db,envelope:signManifest(manifest(7)),expected}),/release_scope_or_revision_invalid/);
  assert.equal(reserveVerifiedRelease({dbPath:x.db,envelope:signManifest(manifest(8)),expected}).release_revision,8);
 }finally{x.close()}
});
test('modified artifact and broader target never claim release',()=>{
 const x=scratch();try{
  const wrong={...manifest(1),target_worker:'shell_worker'};
  assert.throws(()=>reserveVerifiedRelease({dbPath:x.db,envelope:signManifest(wrong),expected}),/release_scope_or_revision_invalid/);
  assert.throws(()=>reserveVerifiedRelease({dbPath:x.db,envelope:signManifest(manifest(1)),expected:{...expected,artifactBytes:Buffer.from('tampered')}}),/artifact_digest_mismatch/);
  assert.equal(readReleaseLedger({dbPath:x.db}).attempts.length,0);
 }finally{x.close()}
});
test('forged signature and different owner public key are refused',()=>{
 const x=scratch();try{
  const fake=signManifest(manifest(1));
  fake.manifest_json=fake.manifest_json.replace('"release_revision":1','"release_revision":2');
  assert.throws(()=>reserveVerifiedRelease({dbPath:x.db,envelope:fake,expected}),/owner_signature_invalid/);
  const wrongKey=generateKeyPairSync('ed25519').publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64');
  assert.throws(()=>reserveVerifiedRelease({dbPath:x.db,envelope:signManifest(manifest(1)),expected:{...expected,pinnedOwnerPublicKeyB64:wrongKey}}),/owner_signature_invalid/);
  assert.equal(readReleaseLedger({dbPath:x.db}).attempts.length,0);
 }finally{x.close()}
});
test('lost trusted ledger is never recreated by a signed release',()=>{
 const x=scratch();try{
  reserveVerifiedRelease({dbPath:x.db,envelope:signManifest(manifest(22)),expected});
  rmSync(x.db,{force:true});
  assert.throws(()=>readReleaseLedger({dbPath:x.db}),/trusted_ledger_denied/);
  assert.throws(()=>reserveVerifiedRelease({dbPath:x.db,envelope:signManifest(manifest(22)),expected}),/trusted_ledger_denied/);
 }finally{x.close()}
});
test('invalid ledger and unsupported completion fail closed',()=>{
 const x=scratch();try{
  const c=reserveVerifiedRelease({dbPath:x.db,envelope:signManifest(manifest(1)),expected});
  assert.throws(()=>finalizeReservedRelease({dbPath:x.db,claimId:c.claim_id,result:'queued'}),/invalid_final_result/);
  assert.throws(()=>readReleaseLedger({dbPath:'/unavailable/owner-gate/ledger.sqlite'}),/trusted_ledger_denied/);
 }finally{x.close()}
});
