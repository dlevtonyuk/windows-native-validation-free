// RESEARCH ONLY. No API calls, secrets, effects, executable transport, or owner grant activation.
// Published Workyard API: PUT replaces the whole timecard; PATCH approve is separate.
// Safe candidate evaluation cannot substitute for an owner-controlled protected broker.
const INT=n=>Number.isSafeInteger(n)&&n>0;
const UNIX=n=>INT(n)&&n>=1577836800;
const DEC=n=>typeof n==='number'&&Number.isFinite(n)&&n>=0&&n<=1;
const EQ=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const ERR=(name)=>name;
const REQUIRED=['id','status','updated_at_unix','start_dt_unix','end_dt_unix','time_approver_id','breaks','cost_allocation_selections'];
const MANDATORY_WRITE=['start_dt_unix','updated_at_unix','end_dt_unix','time_approver_id','breaks','cost_allocation_selections'];
const MUTABLE=new Set([...MANDATORY_WRITE,'reason']);
export const API_CONTRACT=Object.freeze({
  update:Object.freeze({method:'PUT',template:'/orgs/{org_id}/time_cards/{time_card_id}',fullReplacement:true}),
  approve:Object.freeze({method:'PATCH',template:'/orgs/{org_id}/time_cards/{time_card_id}/approve'}),
  limitRequestsPerMinute:60,concurrentListTimeCardsPerApiUser:1,
  source:'https://developers.workyard.com/',actualEffectExecutionEnabled:false
});
function scanAllocations(groups,catalog,errs,prefix){
  if(!Array.isArray(groups)||!groups.length){errs.push(`${prefix}_allocations_not_complete`);return null;}
  const map=new Map(),worksites=new Set();
  for(const group of groups){
    if(!group||!INT(group.work_site_id)||worksites.has(group.work_site_id)||!Array.isArray(group.selections)||!group.selections.length){errs.push(`${prefix}_worksite_invalid_or_repeated`);continue;}
    worksites.add(group.work_site_id);
    let total=0;const projects=new Set();
    for(const p of group.selections){
      if(!p||!INT(p.project_id)||!DEC(p.percent)||p.percent<=0||projects.has(p.project_id)){
        errs.push(`${prefix}_project_or_weight_invalid`);continue;
      }
      projects.add(p.project_id);total+=p.percent;
      const key=`${group.work_site_id}:${p.project_id}`;
      map.set(key,p.percent);
      if(!Array.isArray(p.cost_codes)){errs.push(`${prefix}_codes_not_explicit`);continue;}
      if(p.cost_codes.length){
        const allowed=catalog?.[String(p.project_id)];
        if(!Array.isArray(allowed)){errs.push(`${prefix}_project_catalog_missing`);continue;}
        const seen=new Set();let codeTotal=0;
        for(const c of p.cost_codes){
          if(!c||!INT(c.cost_code_id)||!DEC(c.percent)||c.percent<=0||seen.has(c.cost_code_id)||!allowed.includes(c.cost_code_id)){
            errs.push(`${prefix}_invalid_or_unconfigured_code`);continue;
          }
          seen.add(c.cost_code_id);codeTotal+=c.percent;
        }
        if(Math.abs(codeTotal-1)>0.00001)errs.push(`${prefix}_cost_code_weights_not_one`);
      }
    }
    if(Math.abs(total-1)>0.00001)errs.push(`${prefix}_project_weights_not_one`);
  }
  return map;
}
/** Conservative COST-CODE ONLY candidate; never generates an API request or approval. */
export function assessCostCodeEdit({authoritativeFullSnapshot,proposedReplacement,allowedCodesByProject,reason}){
  const e=[],s=authoritativeFullSnapshot,p=proposedReplacement;
  if(!s||typeof s!=='object'||Array.isArray(s)||!p||typeof p!=='object'||Array.isArray(p)){
    return {candidate:false,errors:['missing_full_snapshot_or_replacement'],effectEnabled:false};
  }
  for(const k of REQUIRED)if(!Object.hasOwn(s,k))e.push(`source_${k}_missing`);
  for(const k of MANDATORY_WRITE)if(!Object.hasOwn(p,k))e.push(`replacement_${k}_missing`);
  if(!INT(s.id))e.push(ERR('invalid_card_id'));
  if(!UNIX(s.updated_at_unix)||!UNIX(s.start_dt_unix)||!UNIX(s.end_dt_unix)||s.end_dt_unix<=s.start_dt_unix)e.push(ERR('source_time_invalid'));
  if(!INT(s.time_approver_id)||!Array.isArray(s.breaks))e.push(ERR('source_approver_or_breaks_missing'));
  if(s.is_editable!==true)e.push(ERR('not_editable_at_source'));
  if(!['approved','submitted'].includes(s.status))e.push(ERR('unverified_status_edit_policy'));
  if(!/^[\s\S]{8,400}$/.test(reason||''))e.push(ERR('reason_missing_or_too_short'));
  if(!UNIX(p.updated_at_unix)||p.updated_at_unix!==s.updated_at_unix)e.push(ERR('stale_snapshot_or_unpinned_version'));
  if(p.start_dt_unix!==s.start_dt_unix||p.end_dt_unix!==s.end_dt_unix)e.push(ERR('time_modified_in_code_only_edit'));
  if(p.time_approver_id!==s.time_approver_id)e.push(ERR('approver_modified_in_code_only_edit'));
  if(!EQ(p.breaks,s.breaks))e.push(ERR('breaks_modified_in_code_only_edit'));
  if(Object.keys(p).some(k=>!MUTABLE.has(k)))e.push(ERR('unknown_replacement_field'));
  if(typeof p.reason==='string'&&p.reason!==reason)e.push(ERR('reason_mismatch'));
  const a=scanAllocations(s.cost_allocation_selections,allowedCodesByProject,e,'source');
  const b=scanAllocations(p.cost_allocation_selections,allowedCodesByProject,e,'replacement');
  if(a&&b&&(a.size!==b.size||[...a].some(([k,v])=>!b.has(k)||Math.abs(v-b.get(k))>0.00001)))e.push(ERR('project_allocations_changed_or_dropped'));
  return Object.freeze({candidate:e.length===0,errors:[...new Set(e)],effectEnabled:false,
    nextGate:'independently_protected_owner_grant_and_live_before_after_readback',
    requestedOperation:'cost_code_edit_only',requestTransport:'NONE',apiDescriptor:API_CONTRACT.update});
}
export function assessTimecardApproval(card){
  const e=[];
  if(!card||typeof card!=='object'||Array.isArray(card))e.push('missing_authoritative_card');
  else{
    if(!INT(card.id)||!UNIX(card.updated_at_unix))e.push('missing_id_or_version');
    if(card.status!=='submitted')e.push('status_not_submitted');
    if(card.is_approvable!==true)e.push('source_not_approvable');
  }
  return Object.freeze({candidate:e.length===0,errors:e,effectEnabled:false,
    nextGate:'independently_protected_owner_grant_and_fresh_status_readback',
    requestTransport:'NONE',apiDescriptor:API_CONTRACT.approve});
}
