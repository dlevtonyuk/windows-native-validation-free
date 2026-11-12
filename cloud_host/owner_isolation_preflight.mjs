// Pure, advisory preflight. All inputs are externally collected facts, not proof.
// Passing synthetic test fixtures does NOT provision or secure a real release lane.
// Always perform a separate negative-access test with the assistant's connected app.
const truth = x => x === true;
const sha40=/^[a-f0-9]{40}$/;
const sha256=/^[a-f0-9]{64}$/;
const workerName=/^[a-z][a-z0-9-]{2,127}$/;

export function evaluateReleaseIsolation(snapshot){
  if(!snapshot||typeof snapshot!=='object'||Array.isArray(snapshot))
    throw Error('invalid_evidence');
  const failures=[],needsVerification=[];
  const fail=(id,pred,msg)=>{if(!pred)failures.push({id,reason:msg})};
  const unverified=(id,pred,msg)=>{if(!pred)needsVerification.push({id,reason:msg})};
  const gh=snapshot.github||{}, cf=snapshot.cloudflare||{}, trust=snapshot.ownerTrust||{};
  fail('private-release-repo',truth(gh.releaseRepositoryPrivate),'Owner release repository must be private');
  fail('separate-repository',typeof gh.releaseRepository==='string'&&!!gh.releaseRepository&&gh.releaseRepository!==gh.developmentRepository,'Release repository must be separate from development');
  fail('app-installation-selection',gh.appRepositorySelection==='selected','Assistant GitHub App must use Only select repositories, never All repositories');
  fail('app-not-installed-to-release',Array.isArray(gh.appAllowedRepositories)&&!gh.appAllowedRepositories.includes(gh.releaseRepository),'Assistant app must not have private release repo access');
  fail('source-not-authority',truth(gh.untrustedWorkflowCannotDeploy),'Untrusted development workflows must have no promotion authority');
  fail('release-code-not-editable',truth(gh.releaseWorkflowOwnerControlled),'Release workflow itself must not be assistant-editable');
  fail('auto-deploy-disabled',cf.autoBuildEnabled===false||truth(cf.untrustedBuildCannotDeploy),'Assistant-writable source must not trigger a production deployment');
  fail('build-token-removed',truth(cf.oldUntrustedDeployTokenRevoked),'Existing untrusted production build token must be revoked');
  fail('owner-token-scoped',trust.promotionTokenRole==='individual-worker-editor'&&
    typeof cf.existingWorker==='string'&&workerName.test(cf.existingWorker)&&trust.tokenTargetWorker===cf.existingWorker,
    'Owner deployment token must be Editor on the exact existing Worker only');
  fail('no-token-in-dev',truth(trust.tokenOnlyInOwnerRepository),'Promotion credentials must not reach assistant-editable build workflows');
  fail('owner-action',trust.releaseTrigger==='owner-manual'&&truth(trust.userAuthenticated),'Owner authenticates and authorizes each production release');
  fail('source-identity',typeof trust.approvedSourceCommit==='string'&&sha40.test(trust.approvedSourceCommit),
    'Exact immutable Git commit must be included in release approval');
  fail('artifact-integrity',typeof trust.approvedArtifactSHA256==='string'&&sha256.test(trust.approvedArtifactSHA256),
    'Owner-approved artifact SHA-256 must be checked against deployed bytes');
  fail('replay-store',truth(trust.independentReplayLedger),'Monotonic release authorization must be stored outside assistant reach');
  fail('separate-signer',truth(trust.ownerPrivateSignerOutsideAssistant),'Owner signing material must not be accessible to the assistant');
  fail('public-worker-health',truth(cf.healthUnaffected),'Existing health and public APIs must pass regression tests after cutover');
  unverified('negative-credential-test',truth(trust.assistantReleaseRepoWriteDeniedByActualAPI),
    'Independently confirm assistant GitHub app cannot write the private repo');
  unverified('negative-worker-test',truth(trust.assistantWorkerDeploymentDeniedByActualAPI),
    'Independently confirm assistant connector cannot deploy Worker');
  unverified('recovery-drill',truth(trust.recoveryDrillPassed),'Perform owner-controlled restore/rollback rehearsal');
  unverified('cost-confirmed',truth(trust.freePlanLimitsConfirmed),'Verify no new paid subscriptions or exceeded free quota');
  return {status:failures.length?'BLOCKED':needsVerification.length?'AWAITING_INDEPENDENT_EVIDENCE':'READY_FOR_OWNER_REVIEW',
    failures,needsVerification,warning:'Advisory only; never creates, approves, or deploys an owner release'};
}
