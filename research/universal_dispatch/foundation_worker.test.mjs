import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {readFileSync} from 'node:fs';
import worker,{FOUNDATION_CRON,SLOT_MS,foundationTick,validateScheduled} from './foundation_worker.mjs';
const schema=readFileSync(new URL('./foundation_schema.sql',import.meta.url),'utf8');
const now=1794834000000;
const schedule={cron:FOUNDATION_CRON,scheduledTime:Math.floor(now/SLOT_MS)*SLOT_MS};
function openDb(){
  const raw=new DatabaseSync(':memory:');
  raw.exec(schema);
  return {raw,DB:{prepare(query){const stmt=raw.prepare(query);return{
    bind(...args){return {async first(){return stmt.get(...args)??null},
                        async run(){const result=stmt.run(...args);return {success:true,meta:{changes:result.changes}}}}},
    async first(){return stmt.get()??null}
  }}}};
}
test('schema has four extension slots, no privileged activation or state transition',()=>{
  const {raw}=openDb();
  assert.equal(raw.prepare('SELECT COUNT(*) AS n FROM foundation_capabilities WHERE enabled=0').get().n,4);
  assert.equal(raw.prepare('SELECT execution_mode FROM foundation_meta WHERE id=1').get().execution_mode,'FOUNDATION_INERT');
  assert.throws(()=>raw.prepare("UPDATE foundation_capabilities SET enabled=1 WHERE capability_id='owner_effect_broker'").run(),/CHECK constraint/i);
  assert.throws(()=>raw.prepare("UPDATE foundation_capabilities SET owner_activation_revision=1").run(),/CHECK constraint/i);
  assert.throws(()=>raw.prepare("INSERT INTO foundation_jobs (job_id,capability_id,source_id,idempotency_key,due_ms,created_ms,state) VALUES ('job_once','cloud_read_adapter','source_one','unique_one',10,10,'running')").run(),/CHECK constraint/i);
  raw.close();
});
test('Cron receipts persist once per actual 5-minute slot and never execute job',async()=>{
  const {raw,DB}=openDb();
  raw.prepare("INSERT INTO foundation_jobs(job_id,capability_id,source_id,idempotency_key,due_ms,created_ms) VALUES ('job_read_1','cloud_read_adapter','source_aaa','weekly_1',10,10)").run();
  raw.prepare("INSERT INTO foundation_jobs(job_id,capability_id,source_id,idempotency_key,due_ms,created_ms) VALUES ('job_effect_1','owner_effect_broker','source_bbb','weekly_1',10,10)").run();
  const controller={...schedule};
  const x=await foundationTick(controller,{DB},now);
  assert.deepEqual({mode:x.mode,executed:x.executed_jobs,held:x.held_due_count},{mode:'FOUNDATION_INERT',executed:0,held:2});
  assert.equal(x.state,'recorded');
  assert.equal((await foundationTick(controller,{DB},now+1000)).state,'duplicate');
  assert.equal(raw.prepare("SELECT COUNT(*) AS n FROM foundation_ticks").get().n,1);
  assert.equal(raw.prepare("SELECT COUNT(*) AS n FROM foundation_jobs WHERE state='held'").get().n,2);
  raw.close();
});
test('Reject wrong Cron, clocks, missing DB and changed schema',async()=>{
  const {raw,DB}=openDb();
  assert.throws(()=>validateScheduled({...schedule,cron:'0 * * * *'},now),/unexpected_trigger/);
  assert.throws(()=>validateScheduled(schedule,now+15*60*1000),/untrusted_schedule_clock/);
  assert.throws(()=>validateScheduled({...schedule,scheduledTime:now+200000},now),/untrusted_schedule_clock/);
  await assert.rejects(foundationTick(schedule,{},now),/missing_isolated_db/);
  assert.equal((await foundationTick(schedule,{DB},now)).state,'recorded');
  raw.close();
});
test('Future jobs remain held and no public API is exposed',async()=>{
  const {raw,DB}=openDb();
  raw.prepare("INSERT INTO foundation_jobs(job_id,capability_id,source_id,idempotency_key,due_ms,created_ms) VALUES ('job_future','device_service','source_aaa','future_one',9999999999999,10)").run();
  assert.equal((await foundationTick(schedule,{DB},now)).held_due_count,0);
  const res=await worker.fetch(new Request('https://example.com/secret'));
  assert.equal(res.status,404);
  assert.equal(res.headers.get('cache-control'),'no-store');
  assert.equal(raw.prepare('SELECT enabled FROM foundation_capabilities WHERE capability_id=?').get('device_service').enabled,0);
  raw.close();
});
test('All route categories are held without a source-effect implementation',async()=>{
  const {raw,DB}=openDb();
  const routes=raw.prepare('SELECT capability_id FROM foundation_capabilities ORDER BY capability_id').all();
  for(const [i,r] of routes.entries()){
    raw.prepare("INSERT INTO foundation_jobs(job_id,capability_id,source_id,idempotency_key,due_ms,created_ms) VALUES (?,?,?,?,?,?)").run(
      'job_'+(i+100),r.capability_id,'source_lab','once_'+(i+100),now-1000,now-2000);
  }
  const out=await foundationTick(schedule,{DB},now);
  assert.equal(out.held_due_count,routes.length);
  assert.equal(out.executed_jobs,0);
  assert.equal(out.external_calls,0);
  raw.close();
});
