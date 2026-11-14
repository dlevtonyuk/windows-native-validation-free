// CWFR primary-Windows read-only aggregate telemetry ingestion; zero devices enrolled at deployment.
// NO remote commands, device enrollment endpoint, general-purpose proxy, or data-reading endpoint.
const ID = /^[0-9a-f]{32}$/;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const TOKEN = /^[a-zA-Z0-9_-]{43}$/;
const KIND = 'aggregate_windows_readonly';
const KEYS = ['commit_used_pct','cpu_used_pct','evidence_kind','observed_ms','process_count','ram_available_mb','ram_total_mb','ram_used_pct','sample_id','schema'];
const HOUR = 3600000;
const RETENTION_CRON = '23 3 * * *';
const response=(status,body,extra={}) => new Response(JSON.stringify(body),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff',...extra}});
const finitePercent=(n,nullable=false)=>nullable&&n===null||(typeof n==='number'&&Number.isFinite(n)&&n>=0&&n<=100);
const whole=(n,lo,hi)=>Number.isSafeInteger(n)&&n>=lo&&n<=hi;
function validateBody(body,now){
  if(!body||typeof body!=='object'||Array.isArray(body)||Object.keys(body).sort().join(',')!==KEYS.join(','))return false;
  return body.schema===1&&body.evidence_kind===KIND&&UUID_V4.test(body.sample_id)&&
    whole(body.observed_ms,1,8640000000000000)&&body.observed_ms>=now-5*60000&&body.observed_ms<=now+90000&&
    finitePercent(body.cpu_used_pct,true)&&finitePercent(body.ram_used_pct)&&
    whole(body.ram_total_mb,128,4194304)&&whole(body.ram_available_mb,0,body.ram_total_mb)&&
    finitePercent(body.commit_used_pct,true)&&whole(body.process_count,1,100000)&&
    Math.abs(body.ram_used_pct-100*(1-body.ram_available_mb/body.ram_total_mb))<=1.5;
}
async function sha256hex(token){const bytes=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(token));return [...new Uint8Array(bytes)].map(b=>b.toString(16).padStart(2,'0')).join('');}
function same(a,b){if(typeof a!=='string'||typeof b!=='string'||a.length!==64||b.length!==64)return false;let d=0;for(let i=0;i<64;i++)d|=a.charCodeAt(i)^b.charCodeAt(i);return d===0;}
async function acceptTelemetry(request,env,nowFn=()=>Date.now()){
  // This is inert without BOTH a user-enabled route and owner-enrolled device hash.
  const url=new URL(request.url);
  if(url.pathname!=='/v1/telemetry'||request.method!=='POST'||url.search!=='')return response(404,{error:'not_found'});
  if(!env?.TELEMETRY_DB?.prepare)return response(503,{error:'temporarily_unavailable'});
  const device=request.headers.get('x-device-id')||'';
  const auth=request.headers.get('authorization')||'';
  const token=auth.startsWith('Bearer ')?auth.slice(7):'';
  if(!ID.test(device)||!TOKEN.test(token))return response(401,{error:'unauthorized'});
  const declared=request.headers.get('content-length');
  if(declared!==null&&(!/^[0-9]+$/.test(declared)||Number(declared)>1200))return response(413,{error:'payload_too_large'});
  if((request.headers.get('content-type')||'').toLowerCase().split(';')[0].trim()!=='application/json')return response(415,{error:'unsupported_media_type'});
  // Bound request-body consumption by BYTES, even when Content-Length is absent
  // or untrusted. request.text() could buffer unlimited attacker-controlled input.
  let raw;
  try {
    const reader=request.body?.getReader();
    if (!reader) return response(400,{error:'invalid_request'});
    const chunks=[];
    let byteCount=0;
    try {
      while(true) {
        const part=await reader.read();
        if(part.done)break;
        byteCount += part.value.byteLength;
        if(byteCount>1200) {
          await reader.cancel().catch(()=>{});
          return response(413,{error:'payload_too_large'});
        }
        chunks.push(part.value);
      }
    } finally {reader.releaseLock();}
    const bytes=new Uint8Array(byteCount);
    let offset=0;
    for(const chunk of chunks) {bytes.set(chunk,offset);offset+=chunk.byteLength;}
    raw=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
  } catch {return response(400,{error:'invalid_request'});}
  let data;try{data=JSON.parse(raw);}catch{return response(400,{error:'invalid_request'});}
  const now=nowFn();
  if(!Number.isSafeInteger(now)||!validateBody(data,now))return response(422,{error:'invalid_reading'});
  try{
    const reg=await env.TELEMETRY_DB.prepare('SELECT token_sha256 FROM device_registry WHERE device_id=? AND active=1').bind(device).first();
    if(!reg||!same(await sha256hex(token),reg.token_sha256))return response(401,{error:'unauthorized'});
    const dupe=await env.TELEMETRY_DB.prepare('SELECT sample_id FROM telemetry_readings WHERE device_id=? AND sample_id=?').bind(device,data.sample_id).first();
    if(dupe)return response(200,{result:'duplicate_ignored'});
    const recent=await env.TELEMETRY_DB.prepare('SELECT MAX(received_ms) AS latest FROM telemetry_readings WHERE device_id=?').bind(device).first();
    if(recent?.latest!==null&&recent?.latest!==undefined&&now-recent.latest<45000)return response(429,{error:'too_frequent'},{'retry-after':'60'});
    // The minimum interval must be enforced by the same atomic SQLite statement
    // as the insert. A SELECT followed by a normal INSERT can race when two
    // simultaneous requests arrive, even if the earlier preflight check passes.
    const result=await env.TELEMETRY_DB.prepare(
      'INSERT INTO telemetry_readings (device_id,sample_id,observed_ms,received_ms,evidence_kind,cpu_used_pct,ram_used_pct,ram_total_mb,ram_available_mb,commit_used_pct,process_count) '
      + 'SELECT ?,?,?,?,?,?,?,?,?,?,? WHERE NOT EXISTS '
      + '(SELECT 1 FROM telemetry_readings WHERE device_id=? AND received_ms>?) '
      + 'ON CONFLICT(device_id,sample_id) DO NOTHING'
    ).bind(device,data.sample_id,data.observed_ms,now,data.evidence_kind,data.cpu_used_pct,data.ram_used_pct,data.ram_total_mb,data.ram_available_mb,data.commit_used_pct,data.process_count,
           device,now-45000).run();
    if(!result?.success)throw new Error('database_unavailable');
    if(result?.meta?.changes===0){
      const saved=await env.TELEMETRY_DB.prepare('SELECT sample_id FROM telemetry_readings WHERE device_id=? AND sample_id=?').bind(device,data.sample_id).first();
      return saved ? response(200,{result:'duplicate_ignored'}) : response(429,{error:'too_frequent'},{'retry-after':'60'});
    }
    return response(202,{result:'accepted'});
  }catch{return response(503,{error:'temporarily_unavailable'});}
}
async function purgeExpired(env,event,nowFn=()=>Date.now()){
  if(event?.cron!==RETENTION_CRON)throw new Error('wrong_retention_cron');
  if(!env?.TELEMETRY_DB?.prepare)throw new Error('missing_d1_binding');
  const time=nowFn();if(!Number.isSafeInteger(time)||time<=7*24*HOUR)throw new Error('invalid_now');
  const r=await env.TELEMETRY_DB.prepare('DELETE FROM telemetry_readings WHERE received_ms<?').bind(time-7*24*HOUR).run();
  if(!r?.success)throw new Error('retention_failed');
  return {removed:r.meta?.changes??0};
}
export default {
  // Cloudflare calls fetch(request, env, executionContext); do not treat ctx as a test clock.
  async fetch(request,env){return acceptTelemetry(request,env);},
  async scheduled(event,env,ctx){const p=purgeExpired(env,event);if(ctx?.waitUntil)ctx.waitUntil(p);else await p;}
};