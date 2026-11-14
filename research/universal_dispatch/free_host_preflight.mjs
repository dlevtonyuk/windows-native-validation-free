// UAG non-deployment research. Pure deterministic capacity/security preflight.
// Source: Cloudflare official limits/pricing, retrieved 2026-11-14.
// This is NOT a Cloudflare account plan or usage measurement and does NOT authorize a release.

export const CF_FREE_LIMITS_2026_11_14 = Object.freeze({
  cronTriggers: 5,
  workerCpuMsPerInvocation: 10,
  workerRequestsPerDay: 100_000,
  workerSubrequestsPerInvocation: 50,
  d1ReadRowsPerDay: 5_000_000,
  d1WriteRowsPerDay: 100_000,
  d1Databases: 10,
  queuesOperationsPerDay: 10_000,
  queueRetentionHours: 24,
  workflowsStepsPerDay: 3_000,
});
const validInteger=(x)=>Number.isSafeInteger(x)&&x>=0;
const validPositive=(x)=>Number.isSafeInteger(x)&&x>0;
function bounded(x,name){if(!validInteger(x))throw new TypeError(`invalid_${name}`);return x;}
function checkedMultiply(a,b){const n=a*b;if(!Number.isSafeInteger(n))throw new RangeError('estimate_overflow');return n;}
function checkedSum(values){const n=values.reduce((a,b)=>a+b,0);if(!Number.isSafeInteger(n))throw new RangeError('estimate_overflow');return n;}

// Never infer quotas or pricing from a Cloudflare 'standard' usage model.
// The actual Free entitlement and current ACCOUNT-WIDE utilization are inputs,
// not inferred by this research code.
export function assessFreeCapacity({
  billingFreeVerified=false,
  cronRulesExisting,
  cronRulesAdded=0,
  existingUsage,
  workloads,
  headroomFraction=0.8,
}) {
  if(typeof billingFreeVerified!=='boolean')throw new TypeError('invalid_billing_free_verified');
  if(!Number.isFinite(headroomFraction)||headroomFraction<=0||headroomFraction>1)
    throw new TypeError('invalid_headroom');
  bounded(cronRulesExisting,'cron_rules_existing');
  bounded(cronRulesAdded,'cron_rules_added');
  if(!Array.isArray(workloads)||workloads.length>500)throw new TypeError('invalid_workloads');
  const fields=['workerRequestsPerDay','d1ReadRowsPerDay','d1WriteRowsPerDay','queuesOperationsPerDay','workflowsStepsPerDay'];
  const base={};
  if(!existingUsage||typeof existingUsage!=='object')throw new TypeError('missing_account_usage');
  for(const field of fields)base[field]=bounded(existingUsage[field],`existing_${field}`);
  const items=[];
  for(const w of workloads){
    if(!w||typeof w!=='object'||typeof w.name!=='string'||!/^[a-z][a-z0-9_-]{2,63}$/.test(w.name))
      throw new TypeError('invalid_workload');
    if(!validPositive(w.runsPerDay))throw new TypeError('invalid_runs_per_day');
    const perRun={};
    for(const f of fields)perRun[f]=bounded(w[f],`workload_${f}`);
    items.push({name:w.name,runsPerDay:w.runsPerDay,totals:Object.fromEntries(fields.map(f=>[f,checkedMultiply(w.runsPerDay,perRun[f])]))});
  }
  const daily=Object.fromEntries(fields.map(f=>[f,checkedSum([base[f],...items.map(x=>x.totals[f])])]));
  const failures=[];
  if(!billingFreeVerified)failures.push('actual_workers_free_entitlement_unverified');
  if(cronRulesExisting+cronRulesAdded>CF_FREE_LIMITS_2026_11_14.cronTriggers)
    failures.push('cron_rules_capacity_exceeded');
  const usage={};
  for(const f of fields){
    const cap=CF_FREE_LIMITS_2026_11_14[f];
    usage[f]={projected:daily[f],hardLimit:cap,headroomBudget:Math.floor(cap*headroomFraction)};
    if(daily[f]>cap)failures.push(`hard_limit_${f}`);
    else if(daily[f]>cap*headroomFraction)failures.push(`headroom_${f}`);
  }
  return {decision:failures.length?'NOT_AUTHORIZED_BY_PREFLIGHT':'WITHIN_PROJECTED_FREE_BUDGET_NOT_DEPLOYMENT_APPROVAL',
    failures,cronRules:{existing:cronRulesExisting,added:cronRulesAdded,accountLimit:CF_FREE_LIMITS_2026_11_14.cronTriggers},
    dailyUsage:usage,workloads:items,
    caveats:['This is an estimate; obtain verified actual usage and plan entitlement before deployment.',
      'Worker CPU time (10 ms) and 50 subrequests are per-invocation runtime limits, not calculated by daily quota projection.',
      'Queue messages expire after 24 hours; a durable D1 job ledger is required for longer offline periods.',
      'No source connection, real data read, external side effect, queue, Worker or schedule is created by this preflight.']};
}

const ID=/^[a-z][a-z0-9_-]{2,63}$/;
const PRIORITIES=new Set(['critical','high','normal','low']);
const ROUTES=new Set(['cloud_readonly','connector_readonly','device_local','owner_guarded_write']);

/**
 * Pure 'due' planner for one Cron and multiple logical schedules.
 * - Never executes jobs, calls the network, or accepts arbitrary command/payload bytes.
 * - An owner-guarded write is never dispatched from this untrusted planner;
 *   it must be independently authorized and executed by a protected effect broker.
 * - connector_readonly is a ChatGPT/plugin lane, NOT directly callable from Worker.
 * - Job source ID, name and due time are metadata only.
 * - maxBatch is a fan-out budget, NOT a claim of future Cloudflare CPU performance.
 */
export function planDueTick({nowMs,jobs,maxBatch=16,deviceOnline=[]}){
  if(!validPositive(nowMs))throw new TypeError('invalid_now');
  if(!Array.isArray(jobs)||jobs.length>1024)throw new TypeError('invalid_jobs');
  if(!validPositive(maxBatch)||maxBatch>32)throw new TypeError('invalid_batch_limit');
  if(!Array.isArray(deviceOnline)||deviceOnline.some(x=>!ID.test(x)))throw new TypeError('invalid_online_devices');
  const online=new Set(deviceOnline),seen=new Set();
  const deferred=[],held=[],buckets=new Map();
  const order=['critical','high','normal','low'];
  for(const j of jobs){
    if(!j||typeof j!=='object'|| ![j.job_id,j.source_id,j.capability].every(x=>typeof x==='string'&&ID.test(x)) ||
       !validPositive(j.due_ms)||!PRIORITIES.has(j.priority)||!ROUTES.has(j.route)||
       !['queued','waiting_for_device'].includes(j.state)||
       (j.route==='device_local' && (typeof j.device_id!=='string'||!ID.test(j.device_id))) ||
       (j.route!=='device_local' && j.device_id!==null))
      throw new TypeError('invalid_job_specification');
    if(seen.has(j.job_id))throw new TypeError('duplicate_job_id');
    seen.add(j.job_id);
    const meta={job_id:j.job_id,source_id:j.source_id,capability:j.capability,due_ms:j.due_ms};
    if(j.due_ms>nowMs){deferred.push({...meta,reason:'not_due'});continue;}
    if(j.route==='owner_guarded_write'){held.push({...meta,reason:'owner_protected_effect_broker_required'});continue;}
    if(j.route==='connector_readonly'){held.push({...meta,reason:'chatgpt_connector_executor_required_not_cloudflare'});continue;}
    if(j.route==='device_local'&&!online.has(j.device_id)){
      held.push({...meta,reason:'device_offline_durable_queue_required'});continue;
    }
    const arr=buckets.get(j.priority)||[];
    arr.push({...meta,route:j.route});buckets.set(j.priority,arr);
  }
  const picked=[];
  for(const priority of order){
    const arr=buckets.get(priority)||[];
    if(picked.length>=maxBatch){
      for(const j of arr)deferred.push({...j,reason:'batch_capacity'});
      continue;
    }
    arr.sort((a,b)=>a.due_ms-b.due_ms||a.job_id.localeCompare(b.job_id));
    const groups=new Map();
    for(const j of arr){const group=groups.get(j.source_id)||[];group.push(j);groups.set(j.source_id,group);}
    const keys=[...groups.keys()].sort();
    while(keys.length&&picked.length<maxBatch){
      for(let i=0;i<keys.length&&picked.length<maxBatch;){
        const key=keys[i],group=groups.get(key);
        picked.push(group.shift());
        if(!group.length)keys.splice(i,1);else i++;
      }
    }
    for(const group of groups.values())for(const j of group)deferred.push({...j,reason:'batch_capacity'});
  }
  return {dispatch:picked,held,deferred,requiresNativeQueueOrSubticks:deferred.some(x=>x.reason==='batch_capacity'),
    guarantee:'PLANNING_ONLY_NOT_EXECUTION_OR_AUTHORIZATION'};
}
