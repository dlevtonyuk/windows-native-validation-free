// Isolated, disposable cloud-runtime integration. No production credentials,
// real device identities, Cloudflare APIs, routes, schedules, or external sends.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {Miniflare} from 'miniflare';

const PATH = fileURLToPath(new URL('../cloud/worker.mjs', import.meta.url));
const SCHEMA = readFileSync(new URL('../cloud/schema.sql',import.meta.url),'utf8');
const D1_ID = '77777777-7777-4777-8777-777777777777';
const DEVICE = 'a'.repeat(32);
const TOKEN = 'B'.repeat(43); // TEST-ONLY fabricated token
const HASH = createHash('sha256').update(TOKEN).digest('hex');
const sendUrl='http://test.invalid/v1/telemetry'; // Local dispatchFetch, NOT a network request
const createSample = (sampleId, now=Date.now()) => ({
  schema:1, evidence_kind:'aggregate_windows_readonly', sample_id:sampleId,
  observed_ms:now, cpu_used_pct:12.5, ram_used_pct:75,
  ram_total_mb:16384, ram_available_mb:4096,
  commit_used_pct:62.1, process_count:160,
});
function request(sample, token=TOKEN, dev=DEVICE) {
  return {method:'POST',headers:{'content-type':'application/json','authorization':'Bearer '+token,'x-device-id':dev},body:JSON.stringify(sample)};
}

// Actual workerd/Miniflare runtime and real D1 binding implementation, not a
// JavaScript mock of env.DB.prepare(). No remote namespace/resource is bound.
test('workerd local D1: HTTP ingress, auth, idempotency, atomic throttle, retention', {timeout:120000}, async () => {
  const mf = new Miniflare({
    modules:true,
    scriptPath:PATH,
    compatibilityDate:'2026-11-14',
    d1Databases:{TELEMETRY_DB:D1_ID},
  });
  try {
    const db=await mf.getD1Database('TELEMETRY_DB');
    // D1.exec() treats comment-only lines as separate fragments; remove SQL
    // comments in this disposable test setup without touching production DDL.
    const cleanSchema=SCHEMA.split('\n').filter(line=>!line.trimStart().startsWith('--')).join('\n');
    for(const statement of cleanSchema.split(';').map(x=>x.trim()).filter(Boolean)) await db.prepare(statement).run();
    const before=await db.prepare('SELECT COUNT(*) AS n FROM device_registry').first();
    assert.equal(before.n,0,'initial identity registry must be empty');
    const denied=await mf.dispatchFetch(sendUrl,request(createSample('123e4567-e89b-42d3-a456-426614174011')));
    assert.equal(denied.status,401,'unknown device must be denied');
    assert.equal((await db.prepare('SELECT COUNT(*) AS n FROM telemetry_readings').first()).n,0);

    await db.prepare('INSERT INTO device_registry (device_id,token_sha256,active,enrolled_ms) VALUES (?,?,1,?)')
      .bind(DEVICE,HASH,Date.now()-1000).run();
    const uuid='123e4567-e89b-42d3-a456-426614174012';
    const sample=createSample(uuid);
    const received=await mf.dispatchFetch(sendUrl,request(sample));
    assert.equal(received.status,202,await received.text());
    assert.equal((await db.prepare('SELECT COUNT(*) AS n FROM telemetry_readings').first()).n,1);

    const retry=await mf.dispatchFetch(sendUrl,request(sample));
    assert.equal(retry.status,200,'idempotent retry accepted as duplicate');
    assert.equal((await retry.json()).result,'duplicate_ignored');
    const second=await mf.dispatchFetch(sendUrl,request(createSample('123e4567-e89b-42d3-a456-426614174013')));
    assert.equal(second.status,429,'minimum interval enforced in runtime D1');
    const badToken=await mf.dispatchFetch(sendUrl,request(createSample('123e4567-e89b-42d3-a456-426614174014'),'C'.repeat(43)));
    assert.equal(badToken.status,401,'bad credential rejected');

    const wrongRoute=await mf.dispatchFetch('http://test.invalid/v1/jobs',{method:'GET'});
    assert.equal(wrongRoute.status,404,'no remote jobs or read endpoints');
    const oversize=await mf.dispatchFetch(sendUrl,{method:'POST',headers:{'content-type':'application/json','authorization':'Bearer '+TOKEN,'x-device-id':DEVICE},body:'x'.repeat(1300)});
    assert.equal(oversize.status,413,'size limit enforced in actual workerd');

    const old = Date.now()-9*24*3600000;
    await db.prepare('UPDATE telemetry_readings SET received_ms=? WHERE device_id=? AND sample_id=?').bind(old,DEVICE,uuid).run();
    const worker=await mf.getWorker();
    const scheduled=await worker.scheduled({cron:'23 3 * * *'});
    assert.equal(scheduled.outcome,'ok','authorized retention event succeeds');
    assert.equal((await db.prepare('SELECT COUNT(*) AS n FROM telemetry_readings').first()).n,0,'expired rows purged');
    assert.equal((await db.prepare('SELECT COUNT(*) AS n FROM device_registry').first()).n,1,'registry remains intact');
    console.log('ISOLATED_WORKER_RUNTIME_D1_INGEST_AND_RETENTION_PASSED');
  } finally {await mf.dispose();}
});