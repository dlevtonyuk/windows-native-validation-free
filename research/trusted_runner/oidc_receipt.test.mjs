import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {reportDigest,receiptAudience,verifyGithubOidcReceipt} from './oidc_receipt.mjs';
const {privateKey,publicKey}=generateKeyPairSync('rsa',{modulusLength:2048});
const pub={...publicKey.export({format:'jwk'}),kid:'test-key-2026',use:'sig',alg:'RS256'};
const jwks={keys:[pub]};
const now=1794838000000, iat=Math.floor(now/1000);
const expected={repositoryId:'123456789',workflowRef:'dlevtonyuk/uag-owner-trusted-runner/.github/workflows/uag-owner-trusted-runner.yml@refs/heads/main',workflowSha:'a'.repeat(40)};
const report={kind:'owner_runner_foundation_read_probe',execution:'NONE',owner_only_activation_status:'NOT_PROVISIONED',
  capability_count:4,enabled_capabilities:0,held_job_count:0,cron_receipts:4,latest_cron_slot_ms:1794836700000};
const b64=x=>Buffer.from(typeof x==='string'?x:JSON.stringify(x)).toString('base64url');
function mint(payload={},header={}){
 const claims={iss:'https://token.actions.githubusercontent.com',aud:receiptAudience(report),
  repository_id:expected.repositoryId,repository_visibility:'private',workflow_ref:expected.workflowRef,
  workflow_sha:expected.workflowSha,ref:'refs/heads/main',runner_environment:'github-hosted',
  iat,nbf:iat,exp:iat+300,jti:'receipt-unique-20261116',run_id:'9001',...payload};
 const h=b64({typ:'JWT',alg:'RS256',kid:pub.kid,...header});
 const p=b64(claims);const input=h+'.'+p;
 return input+'.'+sign('RSA-SHA256',Buffer.from(input),privateKey).toString('base64url');
}
function verify(jwt=mint(),opts={}){return verifyGithubOidcReceipt({jwt,report,jwks,expected,receivedAtMs:now, ...opts})}
test('OIDC signature binds verified aggregate to exact owner-private repository and workflow hash',()=>{
 const x=verify();
 assert.equal(x.valid,true);assert.equal(x.effect_authority,'NONE');
 assert.equal(x.report_sha256,reportDigest(report));
 assert.equal(x.repository_id,expected.repositoryId);
 assert.equal(x.workflow_sha,expected.workflowSha);
});
test('No accepted receipt if aggregate changed, source scope widened or extra fields',()=>{
 const changed={...report,cron_receipts:5};
 assert.throws(()=>verify(mint(),{report:changed}),/oidc_identity_or_audience_mismatch/);
 assert.throws(()=>receiptAudience({...report,employee_names:['A']}),/report_fields_invalid/);
 assert.throws(()=>receiptAudience({...report,enabled_capabilities:1}),/report_scope_invalid/);
});
test('Fail-closed signature, key, algorithm and untrusted token forgery',()=>{
 const forged=mint().split('.');
 forged[1]=b64({iss:'https://token.actions.githubusercontent.com',aud:receiptAudience(report),
  repository_id:expected.repositoryId,repository_visibility:'private',workflow_ref:expected.workflowRef,
  workflow_sha:expected.workflowSha,ref:'refs/heads/main',runner_environment:'github-hosted',
  iat,nbf:iat,exp:iat+300,jti:'receipt-unique-20261116',run_id:'9002'});
 assert.throws(()=>verify(forged.join('.')),/oidc_signature_invalid/);
 assert.throws(()=>verify(mint({},{alg:'none'})),/jwt_header_untrusted/);
 const other={keys:[{...pub,kid:'wrong-key'}]};
 assert.throws(()=>verify(mint(),{jwks:other}),/jwks_key_not_unique/);
});
test('Wrong repository, workflow, ref, public repo and runner fail even if signed',()=>{
 for(const claims of [{repository_id:'7654321'},{workflow_sha:'b'.repeat(40)},
  {ref:'refs/heads/evil'},{repository_visibility:'public'},{runner_environment:'self-hosted'},
  {workflow_ref:'other/private/.github/workflows/w.yml@refs/heads/main'}]){
  assert.throws(()=>verify(mint(claims)),/oidc_identity_or_audience_mismatch/);
 }
});
test('Expired/malformed temporal grants, repeated JWT IDs and unsigned audit are rejected',()=>{
 assert.throws(()=>verify(mint({exp:iat-1})),/oidc_temporal_invalid/);
 assert.throws(()=>verify(mint({exp:iat+901})),/oidc_temporal_invalid/);
 assert.throws(()=>verify(mint({nbf:iat+500})),/oidc_temporal_invalid/);
 assert.throws(()=>verify(mint(),{seenJti:new Set(['receipt-unique-20261116'])}),/oidc_replay_detected/);
 assert.throws(()=>verify('abc.def.ghi'),/jwt_decode_failed/);
});
