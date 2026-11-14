import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
// The production Worker must export only its default handler. To preserve
// precise clock injection for offline tests, append test-only exports to a
// memory-only data URL, never to deployed Worker source.
const deployedSource=readFileSync(new URL('../cloud/worker.mjs',import.meta.url),'utf8');
const testModule=deployedSource+'\nexport {acceptTelemetry,purgeExpired,RETENTION_CRON};\n';
const {default:handler,acceptTelemetry,purgeExpired,RETENTION_CRON}=await import('data:text/javascript;base64,'+Buffer.from(testModule).toString('base64'));
const schema=readFileSync(new URL('../cloud/schema.sql',import.meta.url),'utf8');
const device='a'.repeat(32),token='A'.repeat(43),hash=createHash('sha256').update(token).digest('hex');
const base=Date.parse('2026-11-14T13:00:00Z'),uuid='123e4567-e89b-42d3-a456-426614174000';
function setup(){
 const db=new DatabaseSync(':memory:');db.exec('PRAGMA foreign_keys=ON;'+schema);
 const TABLE={prepare(sql){return {bind(...args){let statement=db.prepare(sql);return {async first(){return statement.get(...args)},async run(){let x=statement.run(...args);return {success:true,meta:{changes:Number(x.changes)}}}}}}}};
 return {db,env:{TELEMETRY_DB:TABLE},insertDevice:(active=1,id=device,h=hash)=>db.prepare('INSERT INTO device_registry (device_id,token_sha256,active,enrolled_ms) VALUES (?,?,?,?)').run(id,h,active,base-1000)};
}
function body(o={}){return {schema:1,evidence_kind:'aggregate_windows_readonly',sample_id:uuid,observed_ms:base-1000,cpu_used_pct:12.5,ram_used_pct:75,ram_total_mb:16384,ram_available_mb:4096,commit_used_pct:62.1,process_count:160,...o}}
function req(payload=body(),{auth=token,dev=device,url='https://example.test/v1/telemetry',method='POST',contentType='application/json'}={}){
 let json=typeof payload==='string'?payload:JSON.stringify(payload);
 return new Request(url,{method,headers:{Authorization:`Bearer ${auth}`,'X-Device-Id':dev,'Content-Type':contentType},body:method==='POST'?json:undefined});
}
async function submit(env,payload,options={},now=base){return acceptTelemetry(req(payload,options),env,()=>now)}
async function json(response){return await response.json()}
test('schema creates exactly 2 dedicated tables and device registry starts empty',()=>{const a=setup();assert.equal(a.db.prepare('SELECT count(*) as n FROM device_registry').get().n,0);assert.equal(a.db.prepare('SELECT count(*) as n FROM telemetry_readings').get().n,0);a.db.close()});
test('unknown device receives generic unauthorized',async()=>{let a=setup();assert.equal((await submit(a.env,body())).status,401);a.db.close()});
test('deactivated owner identity cannot transmit',async()=>{let a=setup();a.insertDevice(0);assert.equal((await submit(a.env,body())).status,401);a.db.close()});
test('invalid bearer rejected and not inserted',async()=>{let a=setup();a.insertDevice();assert.equal((await submit(a.env,body(),{auth:'B'.repeat(43)})).status,401);assert.equal(a.db.prepare('SELECT count(*) as n FROM telemetry_readings').get().n,0);a.db.close()});
test('legitimate read-only aggregate insertion returns accepted',async()=>{let a=setup();a.insertDevice();const r=await submit(a.env,body());assert.equal(r.status,202);assert.deepEqual(await json(r),{result:'accepted'});let row=a.db.prepare('SELECT * FROM telemetry_readings').get();assert.equal(row.device_id,device);assert.equal(row.ram_used_pct,75);assert.equal(row.evidence_kind,'aggregate_windows_readonly');a.db.close()});
test('identical retry idempotent, single row',async()=>{let a=setup();a.insertDevice();await submit(a.env,body());let r=await submit(a.env,body());assert.equal(r.status,200);assert.equal((await json(r)).result,'duplicate_ignored');assert.equal(a.db.prepare('SELECT count(*) AS n FROM telemetry_readings').get().n,1);a.db.close()});
test('under 45 second duplicate-frequency distinct samples blocked',async()=>{let a=setup();a.insertDevice();await submit(a.env,body());const r=await submit(a.env,body({sample_id:'123e4567-e89b-42d3-a456-426614174001'}),{},base+15000);assert.equal(r.status,429);assert.equal(r.headers.get('retry-after'),'60');a.db.close()});
test('new sample after minimum interval allowed',async()=>{let a=setup();a.insertDevice();await submit(a.env,body());const r=await submit(a.env,body({sample_id:'123e4567-e89b-42d3-a456-426614174001',observed_ms:base+60000}),{},base+60000);assert.equal(r.status,202);assert.equal(a.db.prepare('SELECT count(*) AS n FROM telemetry_readings').get().n,2);a.db.close()});
test('stale reading rejected',async()=>{let a=setup();a.insertDevice();assert.equal((await submit(a.env,body({observed_ms:base-300001}))).status,422);a.db.close()});
test('future reading beyond skew rejected',async()=>{let a=setup();a.insertDevice();assert.equal((await submit(a.env,body({observed_ms:base+90001}))).status,422);a.db.close()});
test('extra file/process fields rejected',async()=>{let a=setup();a.insertDevice();assert.equal((await submit(a.env,body({process_name:'chrome',file_path:'C:/private'}))).status,422);a.db.close()});
test('unlisted user property rejected',async()=>{let a=setup();a.insertDevice();assert.equal((await submit(a.env,body({user_name:'secret'}))).status,422);a.db.close()});
test('non-synthetic evidence fixed and exact',async()=>{let a=setup();a.insertDevice();assert.equal((await submit(a.env,body({evidence_kind:'synthetic_scheduler_only'}))).status,422);a.db.close()});
test('invalid CPU percent rejected',async()=>{let a=setup();a.insertDevice();assert.equal((await submit(a.env,body({cpu_used_pct:170}))).status,422);a.db.close()});
test('unmeasurable CPU nullable and accepted',async()=>{let a=setup();a.insertDevice();assert.equal((await submit(a.env,body({cpu_used_pct:null}))).status,202);a.db.close()});
test('inconsistent RAM values rejected',async()=>{let a=setup();a.insertDevice();assert.equal((await submit(a.env,body({ram_used_pct:30}))).status,422);a.db.close()});
test('process_count zero rejected',async()=>{let a=setup();a.insertDevice();assert.equal((await submit(a.env,body({process_count:0}))).status,422);a.db.close()});
test('oversized body rejected',async()=>{let a=setup();a.insertDevice();assert.equal((await submit(a.env,'{"x":"'+ 'a'.repeat(2000)+'"}')).status,413);a.db.close()});
test('unexpected route GET no data disclosure',async()=>{let a=setup();a.insertDevice();const r=await acceptTelemetry(req(undefined,{method:'GET'}),a.env,()=>base);assert.equal(r.status,404);a.db.close()});
test('unexpected request endpoint no data disclosure',async()=>{let a=setup();a.insertDevice();const r=await submit(a.env,body(),{url:'https://example.test/v1/readings'});assert.equal(r.status,404);a.db.close()});
test('querystring rejected',async()=>{let a=setup();a.insertDevice();const r=await submit(a.env,body(),{url:'https://example.test/v1/telemetry?limit=1'});assert.equal(r.status,404);a.db.close()});
test('invalid device pseudonym rejected',async()=>{let a=setup();a.insertDevice();const r=await submit(a.env,body(),{dev:'primary-laptop'});assert.equal(r.status,401);a.db.close()});
test('missing DB binding fails closed',async()=>{const r=await acceptTelemetry(req(),{},()=>base);assert.equal(r.status,503)});
test('wrong content-type rejected',async()=>{let a=setup();a.insertDevice();const r=await submit(a.env,body(),{contentType:'text/plain'});assert.equal(r.status,415);a.db.close()});
test('malformed JSON rejected',async()=>{let a=setup();a.insertDevice();const r=await submit(a.env,'{no');assert.equal(r.status,400);a.db.close()});
test('invalid GUID version rejected',async()=>{let a=setup();a.insertDevice();const r=await submit(a.env,body({sample_id:'123e4567-e89b-12d3-a456-426614174000'}));assert.equal(r.status,422);a.db.close()});
test('wrong retention cron does not delete',async()=>{let a=setup();a.insertDevice();await submit(a.env,body());await assert.rejects(purgeExpired(a.env,{cron:'0 * * * *'},()=>base+9*86400000),/wrong_retention_cron/);assert.equal(a.db.prepare('SELECT count(*) as n FROM telemetry_readings').get().n,1);a.db.close()});
test('retention actually deletes old and preserves fresh',async()=>{let a=setup();a.insertDevice();await submit(a.env,body());let t=base+8*86400000;await a.env.TELEMETRY_DB.prepare('INSERT INTO telemetry_readings (device_id,sample_id,observed_ms,received_ms,evidence_kind,cpu_used_pct,ram_used_pct,ram_total_mb,ram_available_mb,commit_used_pct,process_count) VALUES(?,?,?,?,?,?,?,?,?,?,?)').bind(device,'123e4567-e89b-42d3-a456-426614174002',t,t,'aggregate_windows_readonly',12.5,75,16384,4096,62.1,160).run();const outcome=await purgeExpired(a.env,{cron:RETENTION_CRON},()=>t);assert.equal(outcome.removed,1);assert.equal(a.db.prepare('SELECT count(*) as n FROM telemetry_readings').get().n,1);a.db.close()});
test('retention disabled before activation, no job URL',()=>{assert.equal(RETENTION_CRON,'23 3 * * *')});

// Cloudflare runtime invokes exported fetch(request, env, executionContext), not
// acceptTelemetry(request, env, injectedClock). Regression for a live-only defect.
test('default export fetch receives Cloudflare ExecutionContext without treating it as a clock',async()=>{
  const a=setup();a.insertDevice();const id='123e4567-e89b-42d3-a456-426614174005';
  const current=Date.now();
  const r=await handler.fetch(req(body({sample_id:id,observed_ms:current})),a.env,{waitUntil(){}});
  assert.equal(r.status,202);
  assert.equal(a.db.prepare('SELECT COUNT(*) AS n FROM telemetry_readings').get().n,1);
  a.db.close();
});
test('concurrent distinct samples cannot bypass the atomic minimum interval',async()=>{
  const a=setup();a.insertDevice();
  const first=body({sample_id:'123e4567-e89b-42d3-a456-426614174006'});
  const second=body({sample_id:'123e4567-e89b-42d3-a456-426614174007'});
  const results=await Promise.all([submit(a.env,first,{},base),submit(a.env,second,{},base)]);
  assert.deepEqual(results.map(r=>r.status).sort(),[202,429]);
  assert.equal(a.db.prepare('SELECT COUNT(*) AS n FROM telemetry_readings').get().n,1);
  a.db.close();
});

// In production a requester can omit Content-Length. Refuse large bodies before
// decoding/concatenating; never allocate a whole untrusted body with request.text().
test('large body without Content-Length is rejected with bounded streaming',async()=>{
 const a=setup();a.insertDevice();
 let canceled=false;
 const bodyStream=new ReadableStream({
  start(controller){controller.enqueue(new TextEncoder().encode('x'.repeat(1800)));},
  cancel(){canceled=true;}
 });
 const r=await acceptTelemetry(new Request('https://example.test/v1/telemetry',{
  method:'POST',duplex:'half',headers:{Authorization:'Bearer '+token,'X-Device-Id':device,'Content-Type':'application/json'},body:bodyStream
 }),a.env,()=>base);
 assert.equal(r.status,413);
 assert.equal(canceled,true);
 assert.equal(a.db.prepare('SELECT COUNT(*) AS n FROM telemetry_readings').get().n,0);
 a.db.close();
});
test('multibyte UTF-8 input is bounded by bytes rather than character count',async()=>{
 const a=setup();a.insertDevice();
 const payload='{"extra":"'+ 'é'.repeat(700)+'"}';
 const r=await submit(a.env,payload);
 assert.equal(r.status,413);
 a.db.close();
});
test('invalid UTF-8 is rejected, no database writes',async()=>{
 const a=setup();a.insertDevice();
 const bodyStream=new ReadableStream({start(controller){controller.enqueue(Uint8Array.from([0xff,0xfe]));controller.close();}});
 const r=await acceptTelemetry(new Request('https://example.test/v1/telemetry',{
  method:'POST',duplex:'half',headers:{Authorization:'Bearer '+token,'X-Device-Id':device,'Content-Type':'application/json'},body:bodyStream
 }),a.env,()=>base);
 assert.equal(r.status,400);
 assert.equal(a.db.prepare('SELECT COUNT(*) AS n FROM telemetry_readings').get().n,0);
 a.db.close();
});