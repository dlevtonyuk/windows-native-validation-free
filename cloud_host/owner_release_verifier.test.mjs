import test from "node:test";
import assert from "node:assert/strict";
import {generateKeyPairSync,sign,createHash} from "node:crypto";
import {verifyOwnerRelease} from "./owner_release_verifier.mjs";
const {publicKey,privateKey}=generateKeyPairSync("ed25519");
const pub=publicKey.export({format:"der",type:"spki"}).subarray(-32).toString("base64");
const now=Date.parse("2026-11-12T12:30:00.000Z");
const artifact=Buffer.from("synthetic worker source that has no operations\n","utf8");
const sha=createHash("sha256").update(artifact).digest("hex");
const commit="a".repeat(40);
const scope={repository:"example/synthetic-only",branch:"approved/release",worker:"synthetic-only",
 commit,previousRevision:8,nowMs:now,pinnedOwnerPublicKeyB64:pub,artifactBytes:artifact};
const manifest=()=>({version:1,owner:"local_owner",release_revision:9,
 repository:scope.repository,branch:scope.branch,target_worker:scope.worker,
 source_commit:commit,artifact_sha256:sha,
 issued_utc:new Date(now-1000).toISOString(),expires_utc:new Date(now+3600000).toISOString()});
const signed=(m)=>{const raw=JSON.stringify(m);return {manifest_json:raw,signature_b64:sign(null,Buffer.from(raw),privateKey).toString("base64")}};
const validate=(m,e={})=>verifyOwnerRelease(signed(m),{...scope,...e});
test("valid synthetic release requires original signed SHA-256 source and pinned owner key",()=>{
 const x=validate(manifest());assert.equal(x.approved,true);
 assert.equal(x.sha256,sha);assert.equal(x.release_revision,9);
 assert.equal(x.worker,scope.worker);
});
test("tampering with signed source commit fails",()=>{
 const x=signed(manifest());x.manifest_json=x.manifest_json.replace(commit,"b".repeat(40));
 assert.throws(()=>verifyOwnerRelease(x,scope),/release_scope_or_revision_invalid/);
 const altered=signed(manifest());altered.manifest_json=altered.manifest_json.replace('"release_revision":9','"release_revision":10');
 assert.throws(()=>verifyOwnerRelease(altered,scope),/owner_signature_invalid/);
});
test("artifact source bytes must match signed SHA-256",()=>{
 assert.throws(()=>validate(manifest(),{artifactBytes:Buffer.from("modified source")}),/artifact_digest_mismatch/);
 assert.throws(()=>validate(manifest(),{artifactBytes:undefined}),/missing_actual_artifact/);
});
test("no cross-repository cross-worker or unauthorized branch reuse",()=>{
 const m=manifest();for(const [field,replacement] of [["repository","different/owner"],["target_worker","business-payroll"],["branch","main"],["source_commit","b".repeat(40)]]) {
  const copy={...m,[field]:replacement};
  assert.throws(()=>validate(copy),/release_scope_or_revision_invalid/);
 }
});
test("replay and stale release revisions fail",()=>{
 assert.throws(()=>validate(manifest(),{previousRevision:9}),/release_scope_or_revision_invalid/);
 assert.throws(()=>validate(manifest(),{previousRevision:11}),/release_scope_or_revision_invalid/);
});
test("short expiry, future issue, or expired release denied",()=>{
 const old=manifest();old.expires_utc=new Date(now-100).toISOString();
 assert.throws(()=>validate(old),/expired_or_future_release/);
 const long=manifest();long.expires_utc=new Date(now+90000000).toISOString();
 assert.throws(()=>validate(long),/expired_or_future_release/);
 const future=manifest();future.issued_utc=new Date(now+3600000).toISOString();
 assert.throws(()=>validate(future),/expired_or_future_release/);
});
test("invalid/attacker owner public key fails rather than accepting supplied key",()=>{
 const key=generateKeyPairSync("ed25519").publicKey.export({format:"der",type:"spki"}).subarray(-32).toString("base64");
 assert.throws(()=>validate(manifest(),{pinnedOwnerPublicKeyB64:key}),/owner_signature_invalid/);
 assert.throws(()=>validate(manifest(),{pinnedOwnerPublicKeyB64:"a"}),/malformed_base64/);
});
test("extra permissions or extra fields fail",()=>{
 const m=manifest();m.capabilities={windows_shell:{enabled:true}};
 assert.throws(()=>validate(m),/unexpected_release_fields/);
 const e=signed(manifest());e.admin_override=true;
 assert.throws(()=>verifyOwnerRelease(e,scope),/unexpected_release_fields/);
});
test("invalid or missing owner signature rejected",()=>{
 const e=signed(manifest());e.signature_b64="not-a-signature";
 assert.throws(()=>verifyOwnerRelease(e,scope),/malformed_base64/);
 const f=signed(manifest());f.signature_b64=Buffer.alloc(64).toString("base64");
 assert.throws(()=>verifyOwnerRelease(f,scope),/owner_signature_invalid/);
});
test("invalid authorizing branch scope and stale dates cannot be hidden in signed JSON",()=>{
 const m=manifest();m.release_revision=0;
 assert.throws(()=>validate(m),/release_scope_or_revision_invalid/);
 const malformed=manifest();malformed.issued_utc="yesterday";
 assert.throws(()=>validate(malformed),/invalid_release_dates/);
});
