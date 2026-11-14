// RESEARCH ONLY. Native Cloudflare Cron + local D1 persistent synthetic job-state proof.
// NEVER deploy this as written. No provider credentials, network calls, user content,
// external writes, device operations, arbitrary commands or owner effect routes.
const CRON='0 * * * *';
const HOUR=3_600_000;
const MAX_BATCH=8;
const MAX_DELAY=90*60_000;
const LEASE=10*60_000;
const RETRY=5*60_000;
const ACTIVE_ROUTE='cloud_readonly_mock';
const OPERATIONS=new Set(['observe_ready','fail_first']);
function must(cond,reason){if(!cond)throw Error(reason)}
export function validateController(controller,now=Date.now()){
  must(controller?.cron===CRON,'wrong_cron');
  must(Number.isSafeInteger(controller.scheduledTime)&&controller.scheduledTime>0,'bad_scheduled_time');
  must(Number.isSafeInteger(now)&&now>0,'bad_trusted_clock');
  must(controller.scheduledTime<=now+120000&&now-controller.scheduledTime<=MAX_DELAY,'scheduled_time_out_of_bounds');
  return Math.floor(controller.scheduledTime/HOUR)*HOUR;
}
export function acceptableReadJob(job){
  return !!job&&job.route===ACTIVE_ROUTE&&OPERATIONS.has(job.operation)&&
    typeof job.job_id==='string'&&/^[a-z][a-z0-9_-]{2,63}$/.test(job.job_id)&&
    Number.isSafeInteger(job.attempts)&&job.attempts>=1&&
    Number.isSafeInteger(job.max_attempts)&&job.max_attempts>=1&&job.max_attempts<=5;
}
// Hard-coded simulated read-only effects. This NEVER calls an external system.
export async function syntheticReadAdapter(job){
  must(acceptableReadJob(job),'untrusted_job');
  if(job.operation==='fail_first'&&job.attempts===1)throw Error('injected_retryable_read_failure');
  return {kind:'synthetic_read_only',ok:true,operation:job.operation,job_id:job.job_id};
}
async function runSql(env,sql,...args){
  const x=await env.DB.prepare(sql).bind(...args).run();
  must(x?.success===true,'d1_write_unconfirmed');
  return x;
}
async function completeJob(env,job,now,digest){
  const z=await env.DB.prepare("UPDATE dispatch_jobs SET state='succeeded',completed_ms=?,result_sha256=?,lease_until_ms=NULL,last_error=NULL,last_transition_ms=? WHERE job_id=? AND state='running' AND attempts=? RETURNING job_id").bind(now,digest,now,job.job_id,job.attempts).all();
  // D1's meta.changes may count auditing triggers. Inspect the RETURNING CAS row.
  must(z?.success===true&&z?.results?.length===1&&z.results[0].job_id===job.job_id,'completion_cas_failed');
}
async function failJob(env,job,now,error){
  const terminal=job.attempts>=job.max_attempts,kind=terminal?'deadletter':'retry_queued';
  const msg=String(error?.message||'read_failure').slice(0,80);
  const z=await env.DB.prepare("UPDATE dispatch_jobs SET state=?,due_ms=?,lease_until_ms=NULL,last_error=?,last_transition_ms=? WHERE job_id=? AND state='running' AND attempts=? RETURNING job_id").bind(terminal?'deadletter':'queued',terminal?now:now+RETRY,msg,now,job.job_id,job.attempts).all();
  must(z?.success===true&&z?.results?.length===1&&z.results[0].job_id===job.job_id,'failure_cas_failed');
}
export async function dispatchTick(controller,env,now=Date.now()){
  const slot=validateController(controller,now);
  must(env?.DB?.prepare,'missing_local_d1');
  const ins=await runSql(env,"INSERT INTO dispatch_ticks(slot_ms,triggered_ms) VALUES (?,?) ON CONFLICT(slot_ms) DO NOTHING",slot,controller.scheduledTime);
  // Duplicate scheduled invocations cannot re-dispatch a slot.
  if(ins.meta?.changes!==1)return {slot,duplicate:true,executed:0};
  // Only safe synthetic read jobs may be reclaimed after an expired claim.
  // Owner effects and connector jobs have no executable path here.
  await runSql(env,"UPDATE dispatch_jobs SET state=CASE WHEN attempts>=max_attempts THEN 'deadletter' ELSE 'queued' END,lease_until_ms=NULL,last_error=CASE WHEN attempts>=max_attempts THEN 'expired_mock_lease_attempts_exhausted' ELSE 'expired_mock_lease' END,last_transition_ms=? WHERE route='cloud_readonly_mock' AND state='running' AND lease_until_ms<=?",now,now);
  const claimed=await env.DB.prepare("UPDATE dispatch_jobs SET state='running',attempts=attempts+1,lease_until_ms=?,last_transition_ms=? WHERE job_id IN (SELECT job_id FROM dispatch_jobs WHERE route='cloud_readonly_mock' AND state='queued' AND due_ms<=? AND attempts<max_attempts ORDER BY due_ms,job_id LIMIT ?) RETURNING job_id,route,operation,attempts,max_attempts").bind(now+LEASE,now,now,MAX_BATCH).all();
  must(claimed?.success===true&&Array.isArray(claimed.results),'d1_claim_failed');
  let succeeded=0,requeued=0,deadletter=0;
  for(const job of claimed.results){
    must(acceptableReadJob(job),'claimed_untrusted_job');
    let result;
    try{result=await syntheticReadAdapter(job);}
    catch(e){
      await failJob(env,job,now,e);
      if(job.attempts>=job.max_attempts)deadletter++;else requeued++;
      continue;
    }
    const bytes=new TextEncoder().encode(JSON.stringify(result));
    const sha=[...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(b=>b.toString(16).padStart(2,'0')).join('');
    // Do NOT treat an ambiguous completion write as handler failure.
    // Leave the claim for lease reconciliation instead of attempting two outcomes.
    await completeJob(env,job,now,sha);succeeded++;
  }
  return {slot,duplicate:false,executed:claimed.results.length,succeeded,requeued,deadletter,non_executable_lanes:'held'};
}
const response=(status,payload)=>new Response(JSON.stringify(payload),{status,headers:{'content-type':'application/json','cache-control':'no-store','x-content-type-options':'nosniff'}});
export default {
  async fetch(request){
    const u=new URL(request.url);
    if(request.method==='GET'&&u.pathname==='/health'&&!u.search)return response(200,{service:'uag-durable-dispatch-research',effects:'none',external_connections:'none'});
    return response(404,{error:'no_http_api'});
  },
  async scheduled(controller,env){return dispatchTick(controller,env);}
};
