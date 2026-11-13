import assert from 'node:assert/strict';
import test from 'node:test';
import handler, {recordSyntheticSlot} from './worker.mjs';

const NOW = Date.UTC(2026,10,13,13,0,20);
const CTRL = Object.freeze({cron:'0 * * * *',scheduledTime:NOW});
function fixture() {
  const rows=new Map(); let prepareCalls=0;
  return {rows, get calls(){return prepareCalls}, env:{DB:{prepare(sql){
    prepareCalls++;
    assert.match(sql,/^INSERT INTO synthetic_cron_receipts/);
    return {bind(slot,scheduled){return {async run(){
      if(rows.has(slot))return {success:true,meta:{changes:0}};
      rows.set(slot,scheduled);return {success:true,meta:{changes:1}};
    }}}};
  }}}};
}

test('one synthetic hourly receipt, duplicate is idempotent', async()=>{
  const f=fixture();
  assert.deepEqual(await recordSyntheticSlot(CTRL,f.env,NOW+1000),{slot_ms:Date.UTC(2026,10,13,13),inserted:true});
  assert.deepEqual(await recordSyntheticSlot(CTRL,f.env,NOW+1000),{slot_ms:Date.UTC(2026,10,13,13),inserted:false});
  assert.equal(f.rows.size,1);
});
test('wrong cron fails before touching D1',async()=>{
  const f=fixture(); await assert.rejects(recordSyntheticSlot({...CTRL,cron:'* * * * *'},f.env,NOW),/unapproved_schedule/);assert.equal(f.calls,0);
});
test('invalid future and stale times denied without D1 calls',async()=>{
  const f=fixture();
  await assert.rejects(recordSyntheticSlot(CTRL,f.env,NOW-120001),/out_of_bounds/);
  await assert.rejects(recordSyntheticSlot(CTRL,f.env,NOW+90*60000+1),/out_of_bounds/);
  assert.equal(f.calls,0);
});
test('missing database and failed writes never falsely signal success', async()=>{
  await assert.rejects(recordSyntheticSlot(CTRL,{},NOW),/database_not_bound/);
  const f=fixture(); f.env.DB.prepare=()=>({bind:()=>({run:async()=>({success:false})})});
  await assert.rejects(recordSyntheticSlot(CTRL,f.env,NOW),/receipt_write_not_confirmed/);
});
test('only GET /health is exposed; no HTTP jobs, enable or public receipt query',async()=>{
  const origin='https://research.invalid';
  const health=await handler.fetch(new Request(origin+'/health'));
  assert.equal(health.status,200);
  assert.deepEqual(await health.json(),{service:'uag-synthetic-cron',status:'no_business_capabilities'});
  for(const [path,method] of [['/v1/jobs','POST'],['/enable','POST'],['/status','GET'],['/owner/policy','GET'],['/health?detail=1','GET']]){
    const resp=await handler.fetch(new Request(origin+path,{method}));
    assert.equal(resp.status,404);
  }
});
