// PRIVATE OWNER-REPO TEMPLATE ONLY, NOT THE LIVE FOUNDATION EXECUTOR.
// Copy alongside foundation_read_only.mjs into owner-controlled private repo
// after repository access isolation and one-time owner approval. No public CI
// or ChatGPT tool has credentials for this runner. Aggregates only.
import {verifyFoundationReadOnly} from './foundation_read_only.mjs';
async function main(){
 const required=['UAG_CF_ACCOUNT_ID','UAG_CF_D1_DATABASE_ID','UAG_CF_D1_READ_TOKEN'];
 for(const name of required)if(!process.env[name])throw Error('missing_owner_provisioned_env_'+name);
 const report=await verifyFoundationReadOnly({
   fetcher:fetch,
   accountId:process.env.UAG_CF_ACCOUNT_ID,
   databaseId:process.env.UAG_CF_D1_DATABASE_ID,
   apiToken:process.env.UAG_CF_D1_READ_TOKEN
 });
 process.stdout.write(JSON.stringify(report)+'\n');
}
main().catch(e=>{
  // Never log URL, stack, provider body, token or other private request data.
  const safe=new Set(['invalid_resource_identifier','credential_unavailable',
    'd1_result_untrusted','d1_read_http_401','d1_read_http_403','d1_read_http_429',
    'unexpected_foundation_mode','unexpected_capability_catalog',
    'invalid_capability_row','unexpected_capability_activation',
    'unexpected_queue_state','invalid_receipt_count','invalid_receipt_clock']);
  process.stderr.write('UAG_PROTECTED_READ_PROBE_FAILED:'+(safe.has(e?.code)?e.code:'unclassified')+'\n');
  process.exitCode=1;
});
