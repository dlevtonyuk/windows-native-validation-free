// Research-only source, to be copied by the repository owner into the excluded private runner.
// No credentials embedded. Only GitHub-issued ephemeral OIDC identity is transmitted.
// Never import this dynamically from the assistant-editable repository in trusted execution.
const ENDPOINT='https://uag-owner-signed-receipts.dlevtonyuk.workers.dev/v1/receipt';
const AUDIENCE='uag-owner-receipts-v1';
const PAUSE_MS=1000;
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function retryFetch(url, options, label) {
  for(let attempt=1;attempt<=3;attempt++) {
    try {
      const res=await fetch(url,{...options,redirect:'error',signal:AbortSignal.timeout(12000)});
      if([429,502,503,504].includes(res.status)&&attempt<3) {await sleep(PAUSE_MS);continue;}
      return res;
    } catch(e) {
      if(attempt>=3) throw Error(label+'_TRANSPORT_FAILED');
      await sleep(PAUSE_MS);
    }
  }
  throw Error(label+'_TRANSPORT_FAILED');
}
async function parseJson(res,label) {
  try{return await res.json()}catch{throw Error(label+'_JSON_INVALID')}
}
async function main() {
  const status=process.env.UAG_PROBE_STATUS;
  if(!['success','failure'].includes(status))throw Error('PROBE_STATUS_UNAVAILABLE');
  const requestUrl=process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const requestToken=process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if(!requestUrl||!requestToken)throw Error('GITHUB_OIDC_NOT_ENABLED');
  let oidcUrl;try{oidcUrl=new URL(requestUrl);if(oidcUrl.protocol!=='https:')throw Error('non-HTTPS');}
  catch{throw Error('OIDC_REQUEST_URL_INVALID')}
  oidcUrl.searchParams.set('audience',AUDIENCE);
  const oidc=await retryFetch(oidcUrl.toString(),{headers:{Authorization:'bearer '+requestToken}},'OIDC');
  if(!oidc.ok)throw Error('OIDC_HTTP_'+oidc.status);
  const json=await parseJson(oidc,'OIDC');
  const jwt=json?.value;
  if(typeof jwt!=='string'||jwt.length<64||jwt.length>12000)throw Error('OIDC_RESPONSE_INVALID');
  const response=await retryFetch(ENDPOINT,{method:'POST',headers:{Authorization:'Bearer '+jwt,'Content-Type':'application/json'},body:JSON.stringify({probe_status:status})},'RECEIPT');
  if(!response.ok)throw Error('RECEIPT_HTTP_'+response.status);
  const receipt=await parseJson(response,'RECEIPT');
  if(receipt?.ok!==true)throw Error('RECEIPT_NOT_ACKNOWLEDGED');
  process.stdout.write('SIGNED_RECEIPT_ACKNOWLEDGED:'+status+'\n');
}
main().catch(e=>{
  const allow=/^(?:PROBE_STATUS_UNAVAILABLE|GITHUB_OIDC_NOT_ENABLED|OIDC_REQUEST_URL_INVALID|OIDC_TRANSPORT_FAILED|RECEIPT_TRANSPORT_FAILED|OIDC_RESPONSE_INVALID|OIDC_JSON_INVALID|RECEIPT_JSON_INVALID|OIDC_HTTP_[0-9]{3}|RECEIPT_HTTP_[0-9]{3}|RECEIPT_NOT_ACKNOWLEDGED)$/;
  const category=allow.test(e?.message||'')?e.message:'INTERNAL_REPORTER_ERROR';
  process.stderr.write('SIGNED_RECEIPT_ERROR:'+category+'\n');
  process.exitCode=1;
});
