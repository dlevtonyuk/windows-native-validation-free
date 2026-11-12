import test from 'node:test';
import assert from 'node:assert/strict';
import {evaluateReleaseIsolation} from './owner_isolation_preflight.mjs';
const commit='a'.repeat(40), sha='b'.repeat(64);
const good=()=>({
 github:{developmentRepository:'research/gateway-dev',releaseRepository:'owner/gateway-private-release',
   releaseRepositoryPrivate:true,appRepositorySelection:'selected',
   appAllowedRepositories:['research/gateway-dev','research/windows-lab'],
   untrustedWorkflowCannotDeploy:true,releaseWorkflowOwnerControlled:true},
 cloudflare:{autoBuildEnabled:false,untrustedBuildCannotDeploy:true,
   oldUntrustedDeployTokenRevoked:true,existingWorker:'windows-native-validation-free',healthUnaffected:true},
 ownerTrust:{promotionTokenRole:'individual-worker-editor',
   tokenTargetWorker:'windows-native-validation-free',
   tokenOnlyInOwnerRepository:true,releaseTrigger:'owner-manual',userAuthenticated:true,
   approvedSourceCommit:commit,approvedArtifactSHA256:sha,
   independentReplayLedger:true,ownerPrivateSignerOutsideAssistant:true,
   assistantReleaseRepoWriteDeniedByActualAPI:true,
   assistantWorkerDeploymentDeniedByActualAPI:true,
   recoveryDrillPassed:true,freePlanLimitsConfirmed:true}
});
const check=(mut)=>{const x=good();mut(x);return evaluateReleaseIsolation(x)};
test('all conditions synthesized passes review, never actually deploys',()=>{
 const r=evaluateReleaseIsolation(good());
 assert.equal(r.status,'READY_FOR_OWNER_REVIEW');
 assert.equal(r.warning.includes('never creates'),true);
});
test('GitHub App all-repository grant invalidates owner private release isolation',()=>{
 const r=check(x=>x.github.appRepositorySelection='all');
 assert.equal(r.status,'BLOCKED');assert.ok(r.failures.some(y=>y.id==='app-installation-selection'));
});
test('selection still fails if private release repo is included',()=>{
 const r=check(x=>x.github.appAllowedRepositories.push(x.github.releaseRepository));
 assert.ok(r.failures.some(y=>y.id==='app-not-installed-to-release'));
});
test('no private release repo or shared development repo fails',()=>{
 for(const change of [x=>x.github.releaseRepositoryPrivate=false,
  x=>x.github.releaseRepository=x.github.developmentRepository]){
  assert.equal(check(change).status,'BLOCKED');
 }
});
test('auto-deploy must be disabled and privileged build token revoked',()=>{
 const r=check(x=>{x.cloudflare.autoBuildEnabled=true;x.cloudflare.untrustedBuildCannotDeploy=false;x.cloudflare.oldUntrustedDeployTokenRevoked=false});
 assert.ok(r.failures.some(y=>y.id==='auto-deploy-disabled'));
 assert.ok(r.failures.some(y=>y.id==='build-token-removed'));
});
test('Worker deploy token restricted to exactly designated existing worker',()=>{
 for(const change of [x=>x.ownerTrust.promotionTokenRole='workers-product-editor',
  x=>x.ownerTrust.tokenTargetWorker='unrelated-business',
  x=>x.ownerTrust.tokenOnlyInOwnerRepository=false]){
  assert.equal(check(change).status,'BLOCKED');
 }
});
test('missing owner approval or untrusted code signing always blocks',()=>{
 for(const change of [x=>x.ownerTrust.userAuthenticated=false,
  x=>x.ownerTrust.ownerPrivateSignerOutsideAssistant=false,
  x=>x.ownerTrust.independentReplayLedger=false]){
  assert.equal(check(change).status,'BLOCKED');
 }
});
test('immutable source SHA and compiled artifact SHA are mandatory',()=>{
 for(const change of [x=>x.ownerTrust.approvedSourceCommit='main',
  x=>x.ownerTrust.approvedArtifactSHA256='not-a-hash']){
  assert.equal(check(change).status,'BLOCKED');
 }
});
test('attestation alone does not prove negative-access or recovery testing',()=>{
 const r=check(x=>{x.ownerTrust.assistantReleaseRepoWriteDeniedByActualAPI=false;
 x.ownerTrust.recoveryDrillPassed=false});
 assert.equal(r.status,'AWAITING_INDEPENDENT_EVIDENCE');
 assert.equal(r.failures.length,0);
 assert.ok(r.needsVerification.some(y=>y.id==='negative-credential-test'));
});
test('empty or invalid evidence rejected, no default trust',()=>{
 for(const x of [null,[],undefined]) assert.throws(()=>evaluateReleaseIsolation(x));
 assert.equal(evaluateReleaseIsolation({}).status,'BLOCKED');
});
