import test from 'node:test';
import assert from 'node:assert/strict';
import {REQUIRED_STATUSES,currentSql,beginZoho,pollZoho,downloadZoho,collectWorkyard,reconcile} from './provider_client.mjs';

const A=1000,B=2000;
const response=(status,value,headers={})=>({
  status,headers:{get:(name)=>headers[name]??null},
  json:async()=>value,text:async()=>String(value)
});
const card=(id,status,alloc,seconds=3600)=>({
  id,status,start_dt_unix:1100,updated_at_unix:1500,
  time_summary_v2:{duration_secs:seconds},
  cost_allocations:[{id:alloc,duration_secs:seconds,is_sample_data:false,
    org_project_id:4,job_code_id:9,org_project:{cost_code_ids:[9]}}]
});
const full=()=>({
  start:A,endExclusive:B,
  statuses:{approved:[card(17,'approved',801)],
    processed:[],submitted:[],working:[]}
});
const oneCsv=(rowOverrides={})=>{
  const headings=['t.time_card_id','t.allocation_id','t.allocated_secs',
    't.time_card_status','t.time_card_start_dt_unix',
    't.time_card_updated_at_unix','t.workyard_project_id',
    't.cost_code_id','t.synced_at'];
  const cells=['17','801','3600.00','approved','1100','1500','4','9','2026-11-16 06:15:18'];
  for(const [key,value] of Object.entries(rowOverrides)){
    const index=headings.indexOf('t.'+key);
    if(index>=0)cells[index]=value;
  }
  return headings.join(',')+'\r\n'+cells.join(',')+'\r\n';
};
const provider=(fn)=>(url,options)=>{
  assert.equal(options.method,'GET');
  assert.equal(options.redirect,'error');
  return fn(new URL(url),options);
};
test('SQL filters all three blocks with exact independent bounds',()=>{
  const sql=currentSql(A,B);
  assert.equal((sql.match(/>= 1000/g)||[]).length,3);
  assert.equal((sql.match(/< 2000/g)||[]).length,3);
  assert.ok(sql.startsWith('SELECT '));
  assert.equal(sql.includes('DELETE'),false);
  assert.throws(()=>currentSql(2000,1000),/invalid_interval/);
});
test('Zoho start serializes SELECT config into read-only GET and returns durable job marker',async()=>{
  const seen=[];
  const fake=provider((url,options)=>{
    assert.equal(url.origin,'https://analyticsapi.zoho.com');
    seen.push({url,options});
    assert.equal(url.pathname,'/restapi/v2/bulk/workspaces/200/data');
    const q=JSON.parse(url.searchParams.get('CONFIG'));
    assert.equal(q.responseFormat,'csv');
    assert.equal((q.sqlQuery.match(/>= 1000/g)||[]).length,3);
    assert.equal((q.sqlQuery.match(/< 2000/g)||[]).length,3);
    return response(200,{status:'success',data:{jobId:'999'}});
  });
  const result=await beginZoho({fetcher:fake,token:'fictional-read-token',orgId:1,workspaceId:200,start:A,end:B});
  assert.deepEqual(result,{phase:'poll',jobId:'999',period:{start:A,endExclusive:B}});
  assert.equal(seen.length,1);
  assert.equal(seen[0].options.headers.Authorization,'Zoho-oauthtoken fictional-read-token');
});
test('Zoho asynchronous 1001 to 1002 to 1004 handoff preserves job ID',async()=>{
  const codes=['1001','1002','1004'];let count=0;
  const fake=provider((url)=>{
    assert.equal(url.pathname,'/restapi/v2/bulk/workspaces/200/exportjobs/999');
    return response(200,{status:'success',data:{jobCode:codes[count++],expiryTime:'4000'}});
  });
  const base={fetcher:fake,token:'fictional',orgId:1,workspaceId:200,jobId:'999'};
  assert.deepEqual(await pollZoho(base),{phase:'poll',jobId:'999',code:'1001'});
  assert.deepEqual(await pollZoho(base),{phase:'poll',jobId:'999',code:'1002'});
  assert.deepEqual(await pollZoho(base),{phase:'download',jobId:'999',expiryTimeMs:4000});
  assert.equal(count,3);
});
test('Zoho status errors, impossible state and missing expiry fail closed',async()=>{
  for(const code of ['1003','1005','7777','1004']){
    const fake=provider(()=>response(200,{status:'success',data:{jobCode:code}}));
    await assert.rejects(pollZoho({fetcher:fake,token:'fictional',orgId:1,workspaceId:200,jobId:'999'}));
  }
});
test('Download waits for completed job and checks signed expiry before GET',async()=>{
  let calls=0;
  const fake=provider((url)=>{calls++;assert.equal(url.pathname,'/restapi/v2/bulk/workspaces/200/exportjobs/999/data');return response(200,oneCsv())});
  const base={fetcher:fake,token:'fictional',orgId:1,workspaceId:200,jobId:'999',expiryTimeMs:5000};
  await assert.rejects(downloadZoho({...base,nowMs:5000}),/expired/);
  assert.equal(calls,0);
  assert.match(await downloadZoho({...base,nowMs:4000}),/t.time_card_id/);
  assert.equal(calls,1);
});
test('Workyard collects four status pages sequentially using provider-documented API filters',async()=>{
  let concurrent=0,highest=0,requests=0;
  const fake=provider(async(url,options)=>{
    concurrent++;highest=Math.max(highest,concurrent);requests++;
    assert.equal(url.origin,'https://api.workyard.com');
    assert.equal(url.pathname,'/orgs/9/time_cards');
    assert.equal(url.searchParams.get('start_dt_unix'),'gte:1000+lt:2000');
    assert.equal(url.searchParams.get('limit'),'200');
    const status=url.searchParams.get('status').split(':')[1];
    const data=status==='approved'?[card(17,'approved',801)]:[];
    concurrent--;
    return response(200,{data,meta:{current_page:1,last_page:1,total:data.length}});
  });
  const d=await collectWorkyard({fetcher:fake,token:'fictional',orgId:9,start:A,end:B});
  assert.equal(requests,4);assert.equal(highest,1);
  assert.equal(d.statuses.approved.length,1);
  assert.ok(REQUIRED_STATUSES.every(x=>Array.isArray(d.statuses[x])));
  assert.equal(reconcile(d,oneCsv(),{start:A,end:B}).exact_match,true);
});
test('No unexplained historical rows may be silently accepted',()=>{
  const csv=oneCsv()+'17,899,100,approved,1100,1400,4,9,2026-11-15 05:15:18\r\n';
  const r=reconcile(full(),csv,{start:A,end:B});
  assert.equal(r.exact_match,false);assert.equal(r.extra_in_zoho,1);
});
test('Submitted-card coverage remains missing even when approved subset matches',()=>{
  const data=full();data.statuses.submitted.push(card(19,'submitted',803,1200));
  const r=reconcile(data,oneCsv(),{start:A,end:B});
  assert.equal(r.exact_match,false);
  assert.equal(r.missing_in_zoho,1);
  assert.deepEqual(r.missing_in_zoho_by_status,{submitted:1});
  assert.equal(r.workyard_allocations,2);
  assert.equal(r.zoho_allocations,1);
  assert.equal(r.field_mismatches,0);
  assert.equal(JSON.stringify(r).includes('employee_id'),false);
});
test('A missing approved allocation must never be reported as a submitted backlog',()=>{
  const r=reconcile(full(),oneCsv().split('\r\n')[0]+'\r\n',{start:A,end:B});
  assert.equal(r.exact_match,false);
  assert.deepEqual(r.missing_in_zoho_by_status,{approved:1});
});
test('Field mismatch is detected independently of row completeness',()=>{
  const r=reconcile(full(),oneCsv({cost_code_id:'3'}),{start:A,end:B});
  assert.equal(r.exact_match,false);assert.equal(r.field_mismatches,1);
});
test('Header collisions, missing sync and sample flags reject the source',()=>{
  assert.throws(()=>reconcile(full(),oneCsv().replace('t.synced_at','t.allocation_id'),{start:A,end:B}),/zoho_header_invalid/);
  assert.throws(()=>reconcile(full(),oneCsv({synced_at:''}),{start:A,end:B}),/zoho_missing_sync/);
  const data=full();data.statuses.approved[0].cost_allocations[0].is_sample_data=true;
  assert.throws(()=>reconcile(data,oneCsv(),{start:A,end:B}),/untrusted_allocation/);
});
test('Change in pagination totals fails before any success report',async()=>{
  const fake=provider((url)=>{
    const status=url.searchParams.get('status').split(':')[1];
    if(status==='approved')return response(200,{data:[],meta:{current_page:1,last_page:2,total:2}});
    return response(200,{data:[],meta:{current_page:1,last_page:1,total:0}});
  });
  await assert.rejects(collectWorkyard({fetcher:fake,token:'fictional',orgId:9,start:A,end:B}),/page/);
});
test('Provider rate-limit signals retry but never exposes token contents',async()=>{
  const fake=provider(()=>response(429,'',{'Retry-After':'30'}));
  await assert.rejects(
    beginZoho({fetcher:fake,token:'DO_NOT_LEAK_FICTIONAL_TOKEN',orgId:1,workspaceId:2,start:A,end:B}),
    e=>e.code==='provider_rate_limited'&&e.retryAfterSeconds===30&&!String(e).includes('DO_NOT_LEAK')
  );
});
