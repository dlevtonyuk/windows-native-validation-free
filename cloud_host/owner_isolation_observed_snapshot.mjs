// Snapshot only: verified at 2026-11-12 08:46 America/New_York.
// This is deliberately NOT a live-cloud probe. It never calls external systems.
import {evaluateReleaseIsolation} from './owner_isolation_preflight.mjs';
const observed={
  github:{
    developmentRepository:'dlevtonyuk/windows-native-validation-free',
    releaseRepository:null,
    releaseRepositoryPrivate:false,
    appRepositorySelection:'all',
    appAllowedRepositories:[],
    untrustedWorkflowCannotDeploy:false,
    releaseWorkflowOwnerControlled:false
  },
  cloudflare:{
    existingWorker:'windows-native-validation-free',
    autoBuildEnabled:true,
    untrustedBuildCannotDeploy:false,
    oldUntrustedDeployTokenRevoked:false,
    healthUnaffected:true
  },
  ownerTrust:{
    promotionTokenRole:null,
    tokenTargetWorker:null,
    tokenOnlyInOwnerRepository:false,
    releaseTrigger:null,
    userAuthenticated:false,
    approvedSourceCommit:null,
    approvedArtifactSHA256:null,
    independentReplayLedger:false,
    ownerPrivateSignerOutsideAssistant:false,
    assistantReleaseRepoWriteDeniedByActualAPI:false,
    assistantWorkerDeploymentDeniedByActualAPI:false,
    recoveryDrillPassed:false,
    freePlanLimitsConfirmed:false
  }
};
const result=evaluateReleaseIsolation(observed);
if(result.status!=='BLOCKED'||
   !result.failures.some(x=>x.id==='app-installation-selection')||
   !result.failures.some(x=>x.id==='auto-deploy-disabled'))
  throw Error('owner-trust preflight falsely reported ready');
console.log(JSON.stringify({as_of:'2026-11-12',status:result.status,
  critical_failures:result.failures.filter(x=>['app-installation-selection','auto-deploy-disabled','build-token-removed','private-release-repo'].includes(x.id)).map(x=>x.id),
  proof:'Offline snapshot of previously verified APIs; NOT a current authorization or production test'},null,2));
