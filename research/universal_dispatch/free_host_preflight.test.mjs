import test from 'node:test';
import assert from 'node:assert/strict';
import {assessFreeCapacity,planDueTick,CF_FREE_LIMITS_2026_11_14} from './free_host_preflight.mjs';
const zero={workerRequestsPerDay:0,d1ReadRowsPerDay:0,d1WriteRowsPerDay:0,queuesOperationsPerDay:0,workflowsStepsPerDay:0};
const check=(o={})=>assessFreeCapacity({billingFreeVerified:true,cronRulesExisting:2,cronRulesAdded:0,existingUsage:zero,workloads:[{name:'universal_gateway',runsPerDay:480,workerRequestsPerDay:1,d1ReadRowsPerDay:20,d1WriteRowsPerDay:3,queuesOperationsPerDay:3,workflowsStepsPerDay:0}],...o});
function job(n,route='cloud_readonly',priority='normal',source_id='source_one'){
 return {job_id:`job_${n}`,source_id,capability:'metadata_read',due_ms:10000,priority,route,state:'queued',device_id:route==='device_local'?'device_one':null};
}
test('one real Cron can support many logical hourly checks within model capacity',()=>{
 const r=check();assert.match(r.decision,/WITHIN_PROJECTED/);assert.deepEqual(r.cronRules,{existing:2,added:0,accountLimit:5});
 assert.equal(r.dailyUsage.queuesOperationsPerDay.projected,1440);
});
test('billing verification is mandatory, never infer Free from usage model',()=>{
 assert.ok(check({billingFreeVerified:false}).failures.includes('actual_workers_free_entitlement_unverified'));
});
test('five Cron limit is strict, even when daily volume is low',()=>{
 assert.ok(check({cronRulesExisting:5,cronRulesAdded:1}).failures.includes('cron_rules_capacity_exceeded'));
});
test('per-day queue limit flagged before threshold is crossed',()=>{
 const r=check({workloads:[{name:'too_many_queue_ops',runsPerDay:4800,workerRequestsPerDay:1,d1ReadRowsPerDay:10,d1WriteRowsPerDay:1,queuesOperationsPerDay:3,workflowsStepsPerDay:0}]});
 assert.ok(r.failures.includes('hard_limit_queuesOperationsPerDay'));
});
test('headroom threshold denies risky near-capacity use, not just hard quota',()=>{
 const r=check({workloads:[{name:'near_limit',runsPerDay:4500,workerRequestsPerDay:1,d1ReadRowsPerDay:2,d1WriteRowsPerDay:1,queuesOperationsPerDay:2,workflowsStepsPerDay:0}]});
 assert.ok(r.failures.includes('headroom_queuesOperationsPerDay'));
});
test('Workflows step limit checked even if D1 and Queue are cheap',()=>{
 const r=check({workloads:[{name:'step_cost',runsPerDay:1001,workerRequestsPerDay:1,d1ReadRowsPerDay:1,d1WriteRowsPerDay:1,queuesOperationsPerDay:0,workflowsStepsPerDay:3}]});
 assert.ok(r.failures.includes('hard_limit_workflowsStepsPerDay'));
});
test('D1 read and write daily limits independently checked',()=>{
 const r=check({workloads:[{name:'d1_heavy',runsPerDay:2000,workerRequestsPerDay:1,d1ReadRowsPerDay:2501,d1WriteRowsPerDay:51,queuesOperationsPerDay:0,workflowsStepsPerDay:0}]});
 assert.ok(r.failures.includes('hard_limit_d1ReadRowsPerDay'));
 assert.ok(r.failures.includes('hard_limit_d1WriteRowsPerDay'));
});
test('unverified or omitted account-wide usage fails closed',()=>{
 assert.throws(()=>check({existingUsage:{...zero,queuesOperationsPerDay:undefined}}),/invalid_existing_queuesOperationsPerDay/);
 assert.throws(()=>check({existingUsage:undefined}),/missing_account_usage/);
});
test('negative and fractional values denied',()=>{
 assert.throws(()=>check({cronRulesExisting:-1}),/invalid_cron_rules_existing/);
 assert.throws(()=>check({headroomFraction:1.1}),/invalid_headroom/);
 assert.throws(()=>check({workloads:[{name:'malformed',runsPerDay:0,...zero}]}),/invalid_runs_per_day/);
});
test('integer overflow cannot understate projected use',()=>{
 assert.throws(()=>check({workloads:[{name:'overflow_case',runsPerDay:Number.MAX_SAFE_INTEGER,workerRequestsPerDay:2,d1ReadRowsPerDay:0,d1WriteRowsPerDay:0,queuesOperationsPerDay:0,workflowsStepsPerDay:0}]}),/estimate_overflow/);
});
test('due batch favors critical priority and round-robins source IDs',()=>{
 const jobs=[job('one','cloud_readonly','normal','source_one'),job('two','cloud_readonly','critical','source_one'),job('three','cloud_readonly','critical','source_two'),job('four','cloud_readonly','critical','source_one')];
 const p=planDueTick({nowMs:10000,jobs,maxBatch:3});
 assert.deepEqual(p.dispatch.map(x=>x.job_id),['job_four','job_three','job_two']);
 assert.deepEqual(p.deferred.map(x=>x.job_id),['job_one']);
});
test('owner protected side effects NEVER execute from untrusted planner',()=>{
 const p=planDueTick({nowMs:10000,jobs:[job('write','owner_guarded_write')]});
 assert.deepEqual(p.dispatch,[]);assert.equal(p.held[0].reason,'owner_protected_effect_broker_required');
});
test('ChatGPT connector tools never passed to Cloudflare execution',()=>{
 const p=planDueTick({nowMs:10000,jobs:[job('connector','connector_readonly')]});
 assert.deepEqual(p.dispatch,[]);assert.equal(p.held[0].reason,'chatgpt_connector_executor_required_not_cloudflare');
});
test('device-offline work remains held for durable queue instead of failing or replaying effects',()=>{
 const p=planDueTick({nowMs:10000,jobs:[job('device','device_local')]});
 assert.deepEqual(p.dispatch,[]);assert.equal(p.held[0].reason,'device_offline_durable_queue_required');
});
test('device-local work only eligible when externally observed online',()=>{
 const p=planDueTick({nowMs:10000,jobs:[job('device','device_local')],deviceOnline:['device_one']});
 assert.equal(p.dispatch.length,1);
});
test('capacity backlogs are explicit and never silently dropped',()=>{
 const p=planDueTick({nowMs:10000,jobs:[job('one'),job('two'),job('three')],maxBatch:2});
 assert.equal(p.dispatch.length,2);assert.equal(p.deferred.length,1);assert.equal(p.requiresNativeQueueOrSubticks,true);
});
test('future jobs not dispatched prematurely',()=>{
 const j={...job('later'),due_ms:10001};const p=planDueTick({nowMs:10000,jobs:[j]});
 assert.equal(p.dispatch.length,0);assert.equal(p.deferred[0].reason,'not_due');
});
test('duplicate IDs and malformed input fail closed',()=>{
 assert.throws(()=>planDueTick({nowMs:10000,jobs:[job('dup'),job('dup')]}),/duplicate_job_id/);
 assert.throws(()=>planDueTick({nowMs:10000,jobs:[{...job('bad'),route:'remote_shell'}]}),/invalid_job_specification/);
 assert.throws(()=>planDueTick({nowMs:10000,jobs:[{...job('bad'),device_id:'arbitrary'}]}),/invalid_job_specification/);
});
test('bounded batch size prevents unbounded Cron iteration',()=>{
 assert.throws(()=>planDueTick({nowMs:10000,jobs:[],maxBatch:100}),/invalid_batch_limit/);
 assert.ok(CF_FREE_LIMITS_2026_11_14.workerCpuMsPerInvocation===10);
});
