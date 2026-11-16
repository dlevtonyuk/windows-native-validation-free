// RESEARCH ONLY — un-deployed and unauthenticated Cloudflare Worker candidate.
// This file is not an owner-protected release. The current research branch is
// assistant-editable; it MUST NOT auto-deploy to a credential-bearing Worker.
// Never use Gusto/accounting or Workyard write actions through this module.
import {beginZoho,pollZoho,downloadZoho,collectWorkyard,reconcile} from './provider_client.mjs';
const DB_TABLE='uag_provider_runs';
const MAX_STEP_PER_CRON=2;
const ZOHO_AUTH='https://accounts.zoho.com/oauth/v2/token';
const UTC_DATE_FORMAT=new Intl.DateTimeFormat('en-CA',{timeZone:'America/New_York',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hourCycle:'h23'});
function error(code){const x=new Error(code);x.code=code;return x}
const mustPositive=x=>Number.isSafeInteger(x)&&x>0;
function isoParts(ms){const vals=Object.fromEntries(UTC_DATE_FORMAT.formatToParts(new Date(ms)).filter(p=>p.type!=='literal').map(p=>[p.type,Number(p.value)]));return vals}
export function localMidnightUnix(y,m,d){
  const local=Date.UTC(y,m-1,d,0,0,0);
  if(!Number.isFinite(local))throw error('date_invalid');
  let guess=local+5*3600000;
  for(let i=0;i<4;i++){
    const z=isoParts(guess);
    const seen=Date.UTC(z.year,z.month-1,z.day,z.hour,z.minute,z.second);
    guess+=local-seen;
  }
  const v=isoParts(guess);
  if(v.year!==y||v.month!==m||v.day!==d||v.hour!==0||v.minute!==0)throw error('timezone_conversion_failed');
  return Math.round(guess/1000);
}
export function lastClosedWeek(nowMs){
  if(!mustPositive(nowMs))throw error('now_invalid');
  const d=isoParts(nowMs);const midnight=Date.UTC(d.year,d.month-1,d.day);
  const day=new Date(midnight).getUTCDay();
  const currentMon=midnight-((day+6)%7)*86400000;
  const lastMon=currentMon-7*86400000;
  const dateParts=ms=>{const z=new Date(ms);return [z.getUTCFullYear(),z.getUTCMonth()+1,z.getUTCDate()]};
  return {start:localMidnightUnix(...dateParts(lastMon)),end:localMidnightUnix(...dateParts(currentMon))};
}
function recordKey({start,end}){if(!mustPositive(start)||!mustPositive(end)||end<=start||end-start>8*86400)throw error('bad_week');return 'wyzoho:'+start+':'+end}
async function sql(db,query,...args){return db.prepare(query).bind(...args).run()}
async function row(db,query,...args){return db.prepare(query).bind(...args).first()}
export async function initialise(db,period,nowMs){
  const key=recordKey(period);
  await sql(db,'INSERT OR IGNORE INTO '+DB_TABLE+' (period_key,start_unix,end_unix,updated_ms) VALUES(?,?,?,?)',key,period.start,period.end,nowMs);
  return key;
}
async function claim(db,key,nowMs){
  const result=await sql(db,'UPDATE '+DB_TABLE+' SET lease_until_ms=?,attempt_count=attempt_count+1,revision=revision+1,updated_ms=? WHERE period_key=? AND phase IN (\'new\',\'poll\',\'download\') AND next_due_ms<=? AND (lease_until_ms=0 OR lease_until_ms<?) AND attempt_count<12',nowMs+180000,nowMs,key,nowMs,nowMs);
  if(!result?.meta||result.meta.changes!==1)return null;
  return row(db,'SELECT * FROM '+DB_TABLE+' WHERE period_key=?',key);
}
async function next(db,key,phase,nowMs,params){
  let query,args;
  if(phase==='new'){
    query='UPDATE '+DB_TABLE+' SET phase=\'poll\',zoho_job_id=?,next_due_ms=?,lease_until_ms=0,revision=revision+1,updated_ms=? WHERE period_key=? AND phase=\'new\' AND lease_until_ms>?';
    args=[params.jobId,nowMs+30000,nowMs,key,nowMs];
  }else if(phase==='poll' && params.kind==='pending'){
    query='UPDATE '+DB_TABLE+' SET next_due_ms=?,lease_until_ms=0,revision=revision+1,updated_ms=? WHERE period_key=? AND phase=\'poll\' AND lease_until_ms>?';
    args=[nowMs+30000,nowMs,key,nowMs];
  }else if(phase==='poll' && params.kind==='download'){
    query='UPDATE '+DB_TABLE+' SET phase=\'download\',expiry_ms=?,next_due_ms=?,lease_until_ms=0,revision=revision+1,updated_ms=? WHERE period_key=? AND phase=\'poll\' AND lease_until_ms>?';
    args=[params.expiry,nowMs,nowMs,key,nowMs];
  }else if(phase==='download'){
    const finish=params.result.exact_match?'complete':'review_required';
    query='UPDATE '+DB_TABLE+' SET phase=?,result_sha256=?,aggregate_json=?,lease_until_ms=0,revision=revision+1,updated_ms=? WHERE period_key=? AND phase=\'download\' AND lease_until_ms>?';
    args=[finish,params.hash,JSON.stringify(params.result),nowMs,key,nowMs];
  }else throw error('invalid_stage');
  const r=await sql(db,query,...args);
  if(r?.meta?.changes!==1)throw error('state_conflict');
}
async function fail(db,key,phase,nowMs,code,{fatal=false,delayMs=300000}={}){
  // Never save raw request URL, token, private data, exception object or stack.
  const safe=['provider_rate_limited','zoho_export_expired','zoho_job_1003','zoho_job_1005','provider_no_response','provider_http_500','provider_http_503','workyard_page_count_mismatch','zoho_csv_shape'].includes(code)?code:'provider_execution_unknown';
  if(fatal||phase==='new'){
    // Unknown export-creation outcome cannot safely be retried immediately.
    const r=await sql(db,'UPDATE '+DB_TABLE+' SET phase=\'deadletter\',last_error_code=?,lease_until_ms=0,revision=revision+1,updated_ms=? WHERE period_key=? AND lease_until_ms>?',safe,nowMs,key,nowMs);
    if(r?.meta?.changes!==1)throw error('state_conflict');
    return 'deadletter';
  }
  const r=await sql(db,'UPDATE '+DB_TABLE+' SET next_due_ms=?,last_error_code=?,lease_until_ms=0,revision=revision+1,updated_ms=? WHERE period_key=? AND phase=? AND lease_until_ms>?',nowMs+delayMs,safe,nowMs,key,phase,nowMs);
  if(r?.meta?.changes!==1)throw error('state_conflict');
  return 'deferred';
}
async function tokenForZoho(env,fetcher){
  for(const name of ['ZOHO_CLIENT_ID','ZOHO_CLIENT_SECRET','ZOHO_REFRESH_TOKEN'])if(!env[name]||typeof env[name]!=='string')throw error('owner_credentials_missing');
  const body=new URLSearchParams({refresh_token:env.ZOHO_REFRESH_TOKEN,client_id:env.ZOHO_CLIENT_ID,client_secret:env.ZOHO_CLIENT_SECRET,grant_type:'refresh_token'});
  const res=await fetcher(ZOHO_AUTH,{method:'POST',redirect:'error',body,headers:{'Content-Type':'application/x-www-form-urlencoded'}});
  if(!res||res.status!==200)throw error('zoho_oauth_refresh_unavailable');
  const payload=await res.json();
  if(typeof payload?.access_token!=='string'||!payload.access_token)throw error('zoho_oauth_invalid_response');
  return payload.access_token;
}
async function digestAggregate(obj){
  const encoded=new TextEncoder().encode(JSON.stringify(obj));
  const d=await crypto.subtle.digest('SHA-256',encoded);
  return [...new Uint8Array(d)].map(x=>x.toString(16).padStart(2,'0')).join('');
}
export async function advanceOne({db,env,fetcher,nowMs,period}){
  if(!db||!env||typeof fetcher!=='function'||!mustPositive(nowMs))throw error('runtime_unavailable');
  const key=await initialise(db,period,nowMs);
  const rec=await claim(db,key,nowMs);
  if(!rec)return {state:'already_active_or_not_due'};
  const phase=rec.phase;
  try{
    if(!env.WY_TOKEN||!env.ZOHO_ORG_ID||!env.ZOHO_WORKSPACE_ID||!env.WY_ORG_ID)throw error('owner_credentials_missing');
    const access=await tokenForZoho(env,fetcher);
    const zbase={fetcher,token:access,orgId:env.ZOHO_ORG_ID,workspaceId:env.ZOHO_WORKSPACE_ID};
    if(phase==='new'){
      const created=await beginZoho({...zbase,start:period.start,end:period.end});
      await next(db,key,phase,nowMs,{jobId:created.jobId});
      return {state:'pending',stage:'poll'};
    }
    if(phase==='poll'){
      const current=await pollZoho({...zbase,jobId:rec.zoho_job_id});
      if(current.phase==='poll'){
        await next(db,key,phase,nowMs,{kind:'pending'});
        return {state:'pending',stage:'poll'};
      }
      await next(db,key,phase,nowMs,{kind:'download',expiry:current.expiryTimeMs});
      return {state:'pending',stage:'download'};
    }
    if(phase==='download'){
      const csv=await downloadZoho({...zbase,jobId:rec.zoho_job_id,expiryTimeMs:rec.expiry_ms,nowMs});
      const direct=await collectWorkyard({fetcher,token:env.WY_TOKEN,orgId:env.WY_ORG_ID,start:period.start,end:period.end});
      const result=reconcile(direct,csv,{start:period.start,end:period.end});
      await next(db,key,phase,nowMs,{result,hash:await digestAggregate(result)});
      return {state:result.exact_match?'complete':'review_required',summary:result};
    }
    throw error('stage_unexpected');
  }catch(ex){
    const code=String(ex?.code||'provider_execution_unknown');
    await fail(db,key,phase,nowMs,code,{fatal:code==='zoho_export_expired'||code==='zoho_job_1003'||code==='zoho_job_1005',delayMs:Math.max(30000,Math.min(300000,Number(ex?.retryAfterSeconds||30)*1000))});
    return {state:'failed_or_deferred',code:code==='provider_rate_limited'?'provider_rate_limited':'provider_error'};
  }
}
export async function scheduledResearch(env,nowMs,fetcher){
  if(!env?.DB)throw error('db_unavailable');
  const period=lastClosedWeek(nowMs);
  let result;
  for(let i=0;i<MAX_STEP_PER_CRON;i++){
    result=await advanceOne({db:env.DB,env,fetcher,nowMs,period});
    if(result.state!=='pending'||result.stage!=='download')break;
  }
  return {state:result.state}; // never log or return private raw data
}
export default {
  async scheduled(controller,env,ctx){
    // Disabled in repository research workflow. Activating a live scheduled
    // handler plus credentials and D1 bindings requires express owner approval.
    ctx.waitUntil(scheduledResearch(env,controller.scheduledTime,fetch));
  },
  async fetch(){return new Response('Not found',{status:404,headers:{'Cache-Control':'no-store'}})}
};
