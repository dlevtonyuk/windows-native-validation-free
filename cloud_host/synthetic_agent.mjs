// No business permissions, local Windows execution, or arbitrary code support.
// A synthetic cloud-host test adapter: refuses all operations except an echo probe.
const CAP = 'synthetic_probe';
const OP = 'echo';
const DEVICE = 'cloud_runner';
const safeNonce = /^[a-zA-Z0-9_-]{1,96}$/;

function urlFor(endpoint, path) {
  const origin = new URL(endpoint);
  const loopback = origin.hostname === '127.0.0.1' || origin.hostname === 'localhost';
  if (origin.username || origin.password || origin.search || origin.hash ||
      origin.pathname !== '/' || (origin.protocol !== 'https:' && !(loopback && origin.protocol === 'http:')))
    throw new Error('unsafe_endpoint');
  return new URL(path, origin).toString();
}
async function boundedJson(response, limit=4096) {
  const header = response.headers?.get('content-length');
  if (header && Number(header) > limit) throw new Error('oversized_response');
  if (!response.body) throw new Error('missing_response');
  const reader=response.body.getReader();
  const chunks=[];let size=0;
  try {
    while(true){
      const {done,value}=await reader.read();
      if(done)break;
      size+=value.byteLength;
      if(size>limit) throw new Error('oversized_response');
      chunks.push(value);
    }
  } catch(e) {try{await reader.cancel()}catch{};throw e}
  finally {reader.releaseLock()}
  const out=new Uint8Array(size);let pos=0;
  for(const chunk of chunks){out.set(chunk,pos);pos+=chunk.length}
  const obj=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(out));
  if(!obj || typeof obj!=='object' || Array.isArray(obj))throw new Error('invalid_response');
  return obj;
}
export async function runSyntheticOnce({endpoint,token,fetchImpl=fetch}) {
  if(typeof token!=='string'||token.length<32||token.length>1024)throw new Error('invalid_device_credential');
  if(typeof fetchImpl!=='function')throw new Error('invalid_transport');
  const base=urlFor(endpoint,'/health');
  const origin=new URL(base).origin+'/';
  const claim=await fetchImpl(urlFor(origin,`/v1/device/claim?device=${DEVICE}`),{
    method:'GET',headers:{authorization:'Bearer '+token},signal:AbortSignal.timeout(8000)
  });
  if(claim.status!==200)return {state:'unavailable',http_status:claim.status};
  const data=await boundedJson(claim);
  if(data.state==='empty')return {state:'empty'};
  if(data.state!=='leased'||data.capability!==CAP||data.operation!==OP||data.device!==DEVICE||
     typeof data.job_id!=='string'||!/^[a-z][a-z0-9_-]{2,63}$/.test(data.job_id)||
     !data.payload||typeof data.payload!=='object'||Array.isArray(data.payload)||
     Object.keys(data.payload).sort().join(',')!=='nonce'||
     typeof data.payload.nonce!=='string'|| !safeNonce.test(data.payload.nonce)) {
    // Never execute or acknowledge unknown work; lease will expire to interrupted.
    return {state:'refused_unknown_job'};
  }
  // This operation is a pure in-memory echo: no file, network, device or app effect.
  const payload={job_id:data.job_id,state:'succeeded',result:{kind:'synthetic_probe',nonce:data.payload.nonce}};
  const completed=await fetchImpl(urlFor(origin,'/v1/device/complete'),{
    method:'POST',headers:{authorization:'Bearer '+token,'x-device-id':DEVICE,'content-type':'application/json'},
    body:JSON.stringify(payload),signal:AbortSignal.timeout(8000)
  });
  if(completed.status!==200)return {state:'completion_refused',http_status:completed.status};
  const ack=await boundedJson(completed);
  if(ack.job_id!==data.job_id||ack.state!=='succeeded')throw new Error('invalid_completion_ack');
  return {state:'succeeded',job_id:data.job_id};
}
