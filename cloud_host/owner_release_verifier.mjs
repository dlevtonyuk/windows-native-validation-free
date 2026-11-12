// Research-only, pure release-approval verifier. No network, file or deployment calls.
// This verifier MUST run in a separately protected owner-controlled release process;
// placing it inside an assistant-editable workflow does not create owner exclusivity.
import {createHash,createPublicKey,verify,timingSafeEqual} from "node:crypto";
const SPKI_PREFIX=Buffer.from("302a300506032b6570032100","hex");
const B64=/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const SHA=/^[a-f0-9]{64}$/;
const GIT_SHA=/^[a-f0-9]{40}$/;
const dateFmt=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
const names="artifact_sha256,branch,expires_utc,issued_utc,owner,release_revision,repository,source_commit,target_worker,version";
function strictB64(s,len){
  if(typeof s!=="string"||s.length>512||!B64.test(s))throw Error("malformed_base64");
  const b=Buffer.from(s,"base64");
  if(b.length!==len||b.toString("base64")!==s)throw Error("malformed_base64");
  return b;
}
function exactKeys(o,keys){
  if(!o||typeof o!=="object"||Array.isArray(o)||Object.keys(o).sort().join(",")!==keys)
    throw Error("unexpected_release_fields");
}
function sameHash(a,b){
  if(typeof a!=="string"||!SHA.test(a)||typeof b!=="string"||!SHA.test(b))return false;
  return timingSafeEqual(Buffer.from(a,"hex"),Buffer.from(b,"hex"));
}
export function verifyOwnerRelease(envelope,expected){
  if(!expected||typeof expected!=="object")throw Error("missing_expected_release");
  exactKeys(envelope,"manifest_json,signature_b64");
  if(typeof envelope.manifest_json!=="string"||Buffer.byteLength(envelope.manifest_json)>4096)
    throw Error("invalid_manifest");
  const m=JSON.parse(envelope.manifest_json);
  exactKeys(m,names);
  if(m.version!==1||m.owner!=="local_owner"||
    !Number.isSafeInteger(m.release_revision)||m.release_revision<=expected.previousRevision||
    typeof m.repository!=="string"||m.repository!==expected.repository||
    typeof m.branch!=="string"||m.branch!==expected.branch||
    typeof m.target_worker!=="string"||m.target_worker!==expected.worker||
    !GIT_SHA.test(m.source_commit)||m.source_commit!==expected.commit)
    throw Error("release_scope_or_revision_invalid");
  if(typeof m.issued_utc!=="string"||typeof m.expires_utc!=="string"||
    !dateFmt.test(m.issued_utc)||!dateFmt.test(m.expires_utc))
    throw Error("invalid_release_dates");
  const issued=Date.parse(m.issued_utc),expires=Date.parse(m.expires_utc),now=expected.nowMs??Date.now();
  if(!Number.isFinite(issued)||!Number.isFinite(expires)||expires<=now||
    issued>now+300000||now-issued>86400000||expires-issued>86400000||expires<=issued)
    throw Error("expired_or_future_release");
  if(!Buffer.isBuffer(expected.artifactBytes)&&!(expected.artifactBytes instanceof Uint8Array))
    throw Error("missing_actual_artifact");
  const actualDigest=createHash("sha256").update(expected.artifactBytes).digest("hex");
  if(!sameHash(actualDigest,m.artifact_sha256))
    throw Error("artifact_digest_mismatch");
  const rawPublic=strictB64(expected.pinnedOwnerPublicKeyB64,32);
  const signature=strictB64(envelope.signature_b64,64);
  const key=createPublicKey({key:Buffer.concat([SPKI_PREFIX,rawPublic]),format:"der",type:"spki"});
  if(!verify(null,Buffer.from(envelope.manifest_json,"utf8"),key,signature))
    throw Error("owner_signature_invalid");
  return {approved:true,repository:m.repository,branch:m.branch,commit:m.source_commit,
    worker:m.target_worker,release_revision:m.release_revision,sha256:actualDigest};
}
