// RESEARCH ONLY: GET-only Workyard and Zoho Analytics transport.
// No credentials, organization IDs, private data, production deployment or
// privileged effect routes are present in source or CI fixtures.
// Import into an independently owner-approved protected executor only.
export const REQUIRED_STATUSES=Object.freeze(['approved','processed','submitted','working']);
const ORIGINS=Object.freeze({
  workyard:'https://api.workyard.com',
  zoho:'https://analyticsapi.zoho.com'
});
const FIELDS=Object.freeze([
  'time_card_id','allocation_id','allocated_secs','time_card_status',
  'time_card_start_dt_unix','time_card_updated_at_unix',
  'workyard_project_id','cost_code_id'
]);
const ZOHO_COLUMNS=Object.freeze([...FIELDS,'synced_at']);
function failure(code){const e=new Error(code);e.code=code;return e}
function integer(value,name){
  if(value===null||value===undefined||value===''||typeof value==='boolean'||!Number.isSafeInteger(Number(value)))
    throw failure('invalid_'+name);
  return Number(value);
}
function id(value,name){
  if(value===null||value===undefined||String(value).trim()==='')throw failure('missing_'+name);
  return String(value).trim();
}
function emptyable(value){return value===null||value===undefined?'':String(value).trim()}
function interval(start,end){
  const a=integer(start,'start'),b=integer(end,'end');
  if(a<=0||b<=a||b-a>40*86400)throw failure('invalid_interval');
  return [a,b];
}
function authValue(token){if(typeof token!=='string'||token.trim().length<1)throw failure('missing_provider_token');return token}
async function checkedGet(fetcher,origin,path,params,headers){
  if(typeof fetcher!=='function')throw failure('missing_transport');
  const u=new URL(path,origin);
  if(u.origin!==origin)throw failure('forbidden_origin');
  for(const [k,v] of Object.entries(params||{}))u.searchParams.set(k,String(v));
  const res=await fetcher(u.toString(),{method:'GET',redirect:'error',headers});
  if(!res||!Number.isInteger(res.status))throw failure('provider_no_response');
  if(res.status===429){
    const e=failure('provider_rate_limited');
    const wait=Number(res.headers?.get?.('Retry-After')||0);
    e.retryAfterSeconds=Number.isFinite(wait)&&wait>0?Math.min(wait,300):30;
    throw e;
  }
  if(res.status<200||res.status>=300)throw failure('provider_http_'+res.status);
  return res;
}
function wyHeaders(token){return {'Authorization':'Bearer '+authValue(token),'Accept':'application/json'}}
function zoHeaders(token,orgId){return {
  'Authorization':'Zoho-oauthtoken '+authValue(token),
  'ZANALYTICS-ORGID':id(orgId,'org_id'),
  'Accept':'application/json'
}}
export function currentSql(start,end){
  const [a,b]=interval(start,end);
  // Identical local-time Unix bounds in all three required source filters.
  const table='"Workyard Data - Time Card Details"';
  const filt='"time_card_start_dt_unix" >= '+a+' AND "time_card_start_dt_unix" < '+b;
  return 'SELECT t."time_card_id",t."allocation_id",t."allocated_secs",'+
    't."time_card_status",t."time_card_start_dt_unix",'+
    't."time_card_updated_at_unix",t."workyard_project_id",'+
    't."cost_code_id",t."synced_at" FROM '+table+' t '+
    'INNER JOIN (SELECT "time_card_id",MAX("time_card_updated_at_unix") AS "max_updated" '+
    'FROM '+table+' WHERE '+filt+' GROUP BY "time_card_id") cur '+
    'ON t."time_card_id"=cur."time_card_id" AND t."time_card_updated_at_unix"=cur."max_updated" '+
    'INNER JOIN (SELECT "time_card_id","time_card_updated_at_unix",MAX("synced_at") AS "max_sync" '+
    'FROM '+table+' WHERE '+filt+' GROUP BY "time_card_id","time_card_updated_at_unix") sy '+
    'ON t."time_card_id"=sy."time_card_id" AND t."time_card_updated_at_unix"=sy."time_card_updated_at_unix" '+
    'AND t."synced_at"=sy."max_sync" WHERE t.'+filt.replaceAll('"time_card_start_dt_unix"','"time_card_start_dt_unix"').replace(' AND ',' AND t.');
}
export async function beginZoho({fetcher,token,orgId,workspaceId,start,end}){
  const [a,b]=interval(start,end);
  const res=await checkedGet(fetcher,ORIGINS.zoho,
    '/restapi/v2/bulk/workspaces/'+encodeURIComponent(id(workspaceId,'workspace_id'))+'/data',
    {CONFIG:JSON.stringify({sqlQuery:currentSql(a,b),responseFormat:'csv'})},
    zoHeaders(token,orgId));
  const obj=await res.json();
  if(obj?.status!=='success')throw failure('zoho_export_creation_failed');
  const jobId=id(obj?.data?.jobId,'job_id');
  if(!/^\d+$/.test(jobId))throw failure('invalid_job_id');
  return {phase:'poll',jobId,period:{start:a,endExclusive:b}};
}
export async function pollZoho({fetcher,token,orgId,workspaceId,jobId}){
  const jid=id(jobId,'job_id');
  if(!/^\d+$/.test(jid))throw failure('invalid_job_id');
  const path='/restapi/v2/bulk/workspaces/'+encodeURIComponent(id(workspaceId,'workspace_id'))+'/exportjobs/'+jid;
  const res=await checkedGet(fetcher,ORIGINS.zoho,path,{},zoHeaders(token,orgId));
  const obj=await res.json();
  if(obj?.status!=='success')throw failure('zoho_job_status_failed');
  const code=String(obj?.data?.jobCode||'');
  if(code==='1001'||code==='1002')return {phase:'poll',jobId:jid,code};
  if(code==='1003'||code==='1005')throw failure('zoho_job_'+code);
  if(code!=='1004')throw failure('zoho_unknown_job_code');
  const expiry=Number(obj?.data?.expiryTime);
  if(!Number.isSafeInteger(expiry)||expiry<=0)throw failure('zoho_missing_expiry');
  return {phase:'download',jobId:jid,expiryTimeMs:expiry};
}
export async function downloadZoho({fetcher,token,orgId,workspaceId,jobId,expiryTimeMs,nowMs}){
  const exp=integer(expiryTimeMs,'expiry'),now=integer(nowMs,'now');
  if(now>=exp)throw failure('zoho_export_expired');
  const jid=id(jobId,'job_id');
  if(!/^\d+$/.test(jid))throw failure('invalid_job_id');
  const path='/restapi/v2/bulk/workspaces/'+encodeURIComponent(id(workspaceId,'workspace_id'))+'/exportjobs/'+jid+'/data';
  const res=await checkedGet(fetcher,ORIGINS.zoho,path,{}, {...zoHeaders(token,orgId),Accept:'text/csv'});
  const csv=await res.text();
  if(typeof csv!=='string'||csv.length===0||csv.length>8e6)throw failure('zoho_invalid_csv_size');
  return csv;
}
export async function collectWorkyard({fetcher,token,orgId,start,end,limit=200,maxPages=10}){
  const [a,b]=interval(start,end);
  if(!Number.isInteger(limit)||limit<1||limit>200||!Number.isInteger(maxPages)||maxPages<1||maxPages>10)
    throw failure('invalid_page_budget');
  const result={start:a,endExclusive:b,statuses:{}};
  for(const status of REQUIRED_STATUSES){
    const rows=[];let expectedTotal=null,expectedLast=null;
    for(let page=1;page<=maxPages;page++){
      const res=await checkedGet(fetcher,ORIGINS.workyard,
        '/orgs/'+encodeURIComponent(id(orgId,'org_id'))+'/time_cards',
        {limit,page,status:'eq:'+status,start_dt_unix:'gte:'+a+'+lt:'+b},
        wyHeaders(token));
      const obj=await res.json();
      if(!Array.isArray(obj?.data)||!obj.meta)throw failure('workyard_incomplete_page');
      const meta=obj.meta;
      const reportedPage=integer(meta.current_page,'page');
      const reportedLast=integer(meta.last_page,'last_page');
      const reportedTotal=integer(meta.total,'total');
      if(reportedPage!==page||reportedLast<1||reportedTotal<0)throw failure('workyard_page_mismatch');
      if(expectedTotal===null){expectedTotal=reportedTotal;expectedLast=reportedLast}
      else if(expectedTotal!==reportedTotal||expectedLast!==reportedLast)throw failure('workyard_pagination_changed');
      rows.push(...obj.data);
      if(page===expectedLast)break;
      if(page===maxPages)throw failure('workyard_page_budget_exceeded');
    }
    if(rows.length!==expectedTotal)throw failure('workyard_page_count_mismatch');
    result.statuses[status]=rows;
  }
  return result;
}
function csvTable(content){
  if(typeof content!=='string'||content.length===0)throw failure('missing_csv');
  // RFC 4180 quoting, escaped double quotes and CRLF, without external deps.
  const rows=[];let row=[],cell='',quoted=false;
  const s=content.replace(/^\uFEFF/,'');
  for(let i=0;i<s.length;i++){
    const c=s[i];
    if(c==='"'){
      if(quoted&&s[i+1]==='"'){cell+='"';i++}
      else quoted=!quoted;
    }else if(c===','&&!quoted){row.push(cell);cell=''}
    else if((c==='\n'||c==='\r')&&!quoted){
      if(c==='\r'&&s[i+1]==='\n')i++;
      row.push(cell);rows.push(row);row=[];cell='';
    }else cell+=c;
  }
  if(quoted)throw failure('unclosed_csv_quote');
  if(cell!==''||row.length){row.push(cell);rows.push(row)}
  const header=rows.shift()?.map(x=>x.startsWith('t.')?x.slice(2):x);
  if(!header||new Set(header).size!==header.length||ZOHO_COLUMNS.some(x=>!header.includes(x)))throw failure('zoho_header_invalid');
  const other=new Map();
  for(const cells of rows){
    if(cells.length!==header.length)throw failure('zoho_csv_shape');
    const o=Object.fromEntries(header.map((x,i)=>[x,cells[i]]));
    const key=id(o.allocation_id,'allocation_id');
    if(other.has(key))throw failure('zoho_duplicate_allocation');
    if(!o.synced_at)throw failure('zoho_missing_sync');
    other.set(key,o);
  }
  return other;
}
export function reconcile(workyard,zohoCsv,{start,end}){
  const [a,b]=interval(start,end);
  if(workyard?.start!==a||workyard?.endExclusive!==b)throw failure('workyard_period_mismatch');
  const direct=new Map(),cards=new Set(),statusCounts={};let directSeconds=0;
  for(const status of REQUIRED_STATUSES){
    const rows=workyard?.statuses?.[status];
    if(!Array.isArray(rows))throw failure('workyard_missing_status');
    statusCounts[status]={cards:rows.length,allocations:0,seconds:0};
    for(const card of rows){
      const cardId=id(card.id,'card_id');
      if(cards.has(cardId)||card.status!==status)throw failure('workyard_duplicate_or_status');
      cards.add(cardId);
      const started=integer(card.start_dt_unix,'card_start'),updated=integer(card.updated_at_unix,'card_update');
      if(started<a||started>=b)throw failure('workyard_out_of_range');
      if(!Array.isArray(card.cost_allocations)||card.cost_allocations.length===0)throw failure('workyard_missing_allocations');
      let sum=0;
      for(const alloc of card.cost_allocations){
        const aid=id(alloc.id,'allocation_id'),secs=integer(alloc.duration_secs,'seconds');
        if(secs<0||direct.has(aid)||alloc.is_sample_data!==false)throw failure('workyard_duplicate_or_untrusted_allocation');
        const project=emptyable(alloc.org_project_id),code=emptyable(alloc.job_code_id);
        const configured=alloc.org_project?.cost_code_ids;
        if(!Array.isArray(configured))throw failure('workyard_code_config_unknown');
        direct.set(aid,{time_card_id:cardId,allocation_id:aid,allocated_secs:secs,
          time_card_status:status,time_card_start_dt_unix:started,
          time_card_updated_at_unix:updated,workyard_project_id:project,cost_code_id:code});
        sum+=secs;statusCounts[status].allocations++;statusCounts[status].seconds+=secs;
      }
      if(sum!==integer(card.time_summary_v2?.duration_secs,'card_seconds'))throw failure('workyard_duration_mismatch');
      directSeconds+=sum;
    }
  }
  const other=csvTable(zohoCsv),missing={};let extra=0,mismatches=0,matched=0,zohoSeconds=0;
  for(const [aid,row] of other){
    const seconds=integer(row.allocated_secs,'zoho_seconds');if(seconds<0)throw failure('zoho_invalid_seconds');
    zohoSeconds+=seconds;
    const sourceStart=integer(row.time_card_start_dt_unix,'zoho_start');
    if(sourceStart<a||sourceStart>=b)throw failure('zoho_out_of_range');
    if(!direct.has(aid))extra++;
  }
  for(const [aid,row] of direct){
    const otherRow=other.get(aid);
    if(!otherRow){missing[row.time_card_status]=(missing[row.time_card_status]||0)+1;continue}
    let good=true;
    for(const field of FIELDS){
      const left=row[field],right=otherRow[field];
      const numeric=['allocated_secs','time_card_start_dt_unix','time_card_updated_at_unix'].includes(field);
      if(numeric?(left!==integer(right,'zoho_'+field)):(String(left)!==emptyable(right))){mismatches++;good=false}
    }
    if(good)matched++;
  }
  const missingCount=Object.values(missing).reduce((x,y)=>x+y,0);
  return {
    complete:true,exact_match:missingCount===0&&extra===0&&mismatches===0,
    period:{start:a,endExclusive:b},card_count:cards.size,
    workyard_allocations:direct.size,zoho_allocations:other.size,
    workyard_seconds:directSeconds,zoho_seconds:zohoSeconds,
    exact_allocations:matched,missing_in_zoho:missingCount,
    missing_in_zoho_by_status:missing,extra_in_zoho:extra,
    field_mismatches:mismatches,by_status:statusCounts,
    caveats:['Known statuses only; no proof of all possible provider states',
      'Source reads are not atomic; do not infer Zoho sync timezone',
      'Missing submitted cards are pending coverage, not reconciled matches']
  };
}
