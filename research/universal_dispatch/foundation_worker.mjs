// UAG universal foundation v1: OWNER-APPROVED INFRASTRUCTURE, DENY-ALL EXECUTION.
// No SaaS imports, network calls, access to business data, writes, secrets or effects.
// Source is assistant-editable research; it is NOT an owner-exclusive release.
// This Worker logs Cron evidence and observes metadata-only held jobs.
export const FOUNDATION_CRON='*/5 * * * *';
export const SLOT_MS=5*60*1000;
const MAX_SCHEDULE_DELAY_MS=12*60*1000;
function fail(code){const e=new Error(code);e.code=code;throw e}
function integer(n){return Number.isSafeInteger(n)&&n>0}
export function validateScheduled(controller, nowMs){
  if(controller?.cron!==FOUNDATION_CRON)fail('unexpected_trigger');
  const when=controller?.scheduledTime;
  if(!integer(nowMs)||!integer(when)||when>nowMs+120000||nowMs-when>MAX_SCHEDULE_DELAY_MS)
    fail('untrusted_schedule_clock');
  const slot=Math.floor(when/SLOT_MS)*SLOT_MS;
  if(slot<=0)fail('invalid_slot');
  return slot;
}
export async function foundationTick(controller, env, nowMs=Date.now()){
  const slot=validateScheduled(controller,nowMs);
  if(!env?.DB?.prepare)fail('missing_isolated_db');
  const meta=await env.DB.prepare('SELECT schema_version,execution_mode FROM foundation_meta WHERE id=1').first();
  if(meta?.schema_version!==1||meta?.execution_mode!=='FOUNDATION_INERT')fail('schema_or_mode_not_inert');
  const activated=await env.DB.prepare('SELECT COUNT(*) AS n FROM foundation_capabilities WHERE enabled<>0 OR owner_activation_revision<>0').first();
  if(!activated||activated.n!==0)fail('unexpected_capability_activation');
  const due=await env.DB.prepare("SELECT COUNT(*) AS n FROM foundation_jobs WHERE state='held' AND due_ms<=?").bind(nowMs).first();
  if(!due||!Number.isSafeInteger(due.n)||due.n<0)fail('invalid_queue_metadata');
  // Atomic, idempotent metadata-only receipt. Never claim/execute/approve jobs.
  const result=await env.DB.prepare(
    "INSERT INTO foundation_ticks(slot_ms,triggered_ms,recorded_ms,held_due_count,mode) "+
    "VALUES(?,?,?,?,'FOUNDATION_INERT') ON CONFLICT(slot_ms) DO NOTHING")
    .bind(slot,controller.scheduledTime,nowMs,due.n).run();
  if(result?.success!==true||!Number.isInteger(result?.meta?.changes))fail('tick_write_unverified');
  return {state:result.meta.changes===1?'recorded':'duplicate',slot,held_due_count:due.n,
    mode:'FOUNDATION_INERT',executed_jobs:0,external_calls:0};
}
const notFound=()=>new Response('Not found',{status:404,headers:{'content-type':'text/plain','cache-control':'no-store'}});
export default {
  // No public API, including health or administrative surfaces.
  async fetch(){return notFound()},
  async scheduled(controller,env,ctx){ctx.waitUntil(foundationTick(controller,env));}
};
