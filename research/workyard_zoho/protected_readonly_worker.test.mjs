import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {readFileSync,mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {advanceOne,lastClosedWeek,localMidnightUnix} from './protected_readonly_worker.mjs';

const SCHEMA=readFileSync(new URL('./durable_provider.sql',import.meta.url),'utf8');
const env={WY_TOKEN:'fictional-admin-token',WY_ORG_ID:'9',ZOHO_CLIENT_ID:'fictional-client',
 ZOHO_CLIENT_SECRET:'fictional-secret',ZOHO_REFRESH_TOKEN:'fictional-refresh',
 ZOHO_ORG_ID:'1',ZOHO_WORKSPACE_ID:'200'};
function response(status,thing,asText=false){return {status,headers:{get:()=>null},json:async()=>thing,text:async()=>asText?thing:JSON.stringify(thing)}}
const card=(id,status,aid,seconds=3600)=>({id,status,start_dt_unix:1100,updated_at_unix:1500,
 time_summary_v2:{duration_secs:seconds},cost_allocations:[{id:aid,duration_secs:seconds,
 is_sample_data:false,org_project_id:4,job_code_id:9,org_project:{cost_code_ids:[9]}}]});
function fakeTransport({submitted=false}={}){
 let polls=0,created=0,downloads=0,cardRequests=0,tokenRefreshes=0,unexpected=0;
 const csv='t.time_card_id,t.allocation_id,t.allocated_secs,t.time_card_status,t.time_card_start_dt_unix,t.time_card_updated_at_unix,t.workyard_project_id,t.cost_code_id,t.synced_at\r\n17,801,3600.00,approved,1100,1500,4,9,2026-11-16 06:15:18\r\n';
 return {
   fetcher:async(url,opts)=>{
     const x=new URL(url);
     if(x.hostname==='accounts.zoho.com'){
       assert.equal(opts.method,'POST');tokenRefreshes++;
       const body=opts.body;assert.equal(body.get('grant_type'),'refresh_token');
       return response(200,{access_token:'fictional-access'});
     }
     if(x.hostname==='analyticsapi.zoho.com'){
       assert.equal(opts.method,'GET');
       if(x.pathname.endsWith('/data')&&x.searchParams.has('CONFIG')){created++;return response(200,{status:'success',data:{jobId:'999'}})}
       if(x.pathname.endsWith('/999')){const code=['1001','1002','1004'][Math.min(polls++,2)];return response(200,{status:'success',data:{jobCode:code,expiryTime:'999999999999'}})}
       if(x.pathname.endsWith('/999/data')){downloads++;return response(200,csv,true)}
     }
     if(x.hostname==='api.workyard.com'){
       assert.equal(opts.method,'GET');cardRequests++;
       const status=x.searchParams.get('status').split(':')[1];
       let rows=[];
       if(status==='approved')rows=[card(17,'approved',801)];
       if(status==='submitted'&&submitted)rows=[card(18,'submitted',802,1200)];
       return response(200,{data:rows,meta:{current_page:1,last_page:1,total:rows.length}});
     }
     unexpected++;throw new Error('unexpected network target '+x.hostname+x.pathname);
   },
   counts:()=>({polls,created,downloads,cardRequests,tokenRefreshes,unexpected})
 }
}
function makeDb(){
 const db=new DatabaseSync(':memory:');db.exec(SCHEMA);
 return {
  raw:db,
  prepare(q){const stmt=db.prepare(q);return {bind(...args){return {async run(){const r=stmt.run(...args);return {meta:{changes:r.changes}}},async first(){return stmt.get(...args)||null}}}}},
  get(){return db.prepare('SELECT phase,zoho_job_id,result_sha256,aggregate_json FROM uag_provider_runs').get()},
  events(){return db.prepare('SELECT event_kind FROM uag_provider_events ORDER BY event_id').all().map(x=>x.event_kind)}
 }
}
test('DST-safe local Monday boundaries for fall and spring transitions',()=>{
 const fall=lastClosedWeek(Date.UTC(2026,10,2,12));
 assert.equal(fall.start,Date.UTC(2026,9,26,4)/1000);
 assert.equal(fall.end,Date.UTC(2026,10,2,5)/1000);
 assert.equal(fall.end-fall.start,169*3600);
 const spring=lastClosedWeek(Date.UTC(2026,2,9,12));
 assert.equal(spring.start,Date.UTC(2026,2,2,5)/1000);
 assert.equal(spring.end,Date.UTC(2026,2,9,4)/1000);
 assert.equal(spring.end-spring.start,167*3600);
 assert.equal(localMidnightUnix(2026,11,16),Date.UTC(2026,10,16,5)/1000);
});
test('Durable GET-only adapter survives pending Zoho states and completes without duplicate export',async()=>{
 const db=makeDb(),f=fakeTransport(),period={start:1000,end:2000};const base=1000000;
 const call=nowMs=>advanceOne({db,env,fetcher:f.fetcher,nowMs,period});
 const a=await call(base);assert.deepEqual(a,{state:'pending',stage:'poll'});
 assert.equal((await call(base+1000)).state,'already_active_or_not_due');
 assert.equal((await call(base+30000)).state,'pending');
 assert.equal((await call(base+60000)).state,'pending');
 assert.equal((await call(base+90000)).stage,'download');
 const done=await call(base+90000);
 assert.equal(done.state,'complete');
 assert.equal(done.summary.exact_allocations,1);
 assert.equal(db.get().phase,'complete');
 assert.equal(db.get().result_sha256.length,64);
 assert.equal(f.counts().created,1);
 assert.equal(f.counts().downloads,1);
 assert.equal(f.counts().cardRequests,4);
 assert.equal(f.counts().unexpected,0);
 assert.ok(db.events().includes('reconciled'));
 assert.equal((await call(base+120000)).state,'already_active_or_not_due');
 db.raw.close();
});
test('Submitted-card mismatch is terminal review_required, not false success',async()=>{
 const db=makeDb(),f=fakeTransport({submitted:true}),period={start:1000,end:2000};const base=1000000;
 const call=nowMs=>advanceOne({db,env,fetcher:f.fetcher,nowMs,period});
 await call(base);await call(base+30000);await call(base+60000);await call(base+90000);
 const done=await call(base+90000);
 assert.equal(done.state,'review_required');
 assert.deepEqual(done.summary.missing_in_zoho_by_status,{submitted:1});
 assert.equal(db.get().phase,'review_required');
 assert.ok(db.events().includes('review_required'));
 db.raw.close();
});
test('No owner-provisioned credentials fail to deadletter without network attempts',async()=>{
 const db=makeDb();let called=false;
 const r=await advanceOne({db,env:{DB:db},fetcher:()=>{called=true;throw Error('network invoked')},nowMs:1000000,period:{start:1000,end:2000}});
 assert.equal(r.state,'failed_or_deferred');
 assert.equal(db.get().phase,'deadletter');
 assert.equal(called,false);
 db.raw.close();
});
