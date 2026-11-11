import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {createEncryptedOwnerVault,signOwnerPolicy,verifyOwnerBundle} from './owner_policy_vault.mjs';

const password='synthetic-public-fixture-only-long-passphrase-0001';
const now=Date.parse('2026-11-11T12:00:00.000Z');
const p=(enabled=false)=>({version:1,owner:'local_owner',revision:1,
  expires_utc:new Date(now+24*60*60*1000).toISOString(),
  capabilities:{synthetic_probe:{enabled,devices:['cloud_runner'],operations:['echo']}}});
const clone=x=>structuredClone(x);

test('private Ed25519 key is stored only encrypted in owner-controlled prototype vault',()=>{
  const v=createEncryptedOwnerVault(password,new Date(now));
  assert.equal(v.version,'uag-owner-key-v1');
  assert.equal(Buffer.from(v.public_key_b64,'base64').length,32);
  assert.equal(Buffer.from(v.iv_b64,'base64').length,12);
  assert.equal(Buffer.from(v.tag_b64,'base64').length,16);
  assert.ok(v.ciphertext_b64.length>70);
  assert.equal(JSON.stringify(v).includes('BEGIN PRIVATE KEY'),false);
  assert.equal(JSON.stringify(v).includes(password),false);
});

test('owner signature matches native Cloudflare Worker WebCrypto Ed25519 verification',async()=>{
  const v=createEncryptedOwnerVault(password,new Date(now));
  const bundle=signOwnerPolicy(v,password,p(true),now);
  assert.equal(verifyOwnerBundle(bundle),true);
  const publicKey=await webcrypto.subtle.importKey('raw',
    Buffer.from(bundle.owner_public_key_b64,'base64'),{name:'Ed25519'},false,['verify']);
  assert.equal(await webcrypto.subtle.verify('Ed25519',publicKey,
    Buffer.from(bundle.owner_policy_signature_b64,'base64'),
    new TextEncoder().encode(bundle.owner_policy_json)),true);
  const modified=clone(bundle);
  modified.owner_policy_json=modified.owner_policy_json.replace('"enabled":true','"enabled":false');
  assert.equal(verifyOwnerBundle(modified),false);
});

test('wrong passphrase and ciphertext tampering never produce a signature',()=>{
  const v=createEncryptedOwnerVault(password,new Date(now));
  assert.throws(()=>signOwnerPolicy(v,'a-different-public-test-passphrase-0000001',p(),now),
    /owner_vault_decryption_failed/);
  const changed=clone(v);const bytes=Buffer.from(changed.ciphertext_b64,'base64');
  bytes[0]^=1;changed.ciphertext_b64=bytes.toString('base64');
  assert.throws(()=>signOwnerPolicy(changed,password,p(),now),/owner_vault_decryption_failed/);
  const swapped=clone(v);swapped.public_key_b64=Buffer.alloc(32,9).toString('base64');
  assert.throws(()=>signOwnerPolicy(swapped,password,p(),now),/owner_vault_decryption_failed/);
});

test('invalid owner policies, broad expiry and unsupported grant fields rejected',()=>{
  const v=createEncryptedOwnerVault(password,new Date(now));
  const candidates=[];
  let t=clone(p());t.revision=0;candidates.push(t);
  t=clone(p());t.expires_utc=new Date(now+200*24*60*60*1000).toISOString();candidates.push(t);
  t=clone(p());t.expires_utc=new Date(now-1000).toISOString();candidates.push(t);
  t=clone(p());t.capabilities.synthetic_probe.operations=['run_shell','echo','run_shell'];candidates.push(t);
  t=clone(p());t.capabilities.synthetic_probe.devices=['../../pc'];candidates.push(t);
  t=clone(p());t.capabilities.synthetic_probe.extra_access=true;candidates.push(t);
  t=clone(p());t.owner='attacker';candidates.push(t);
  t=clone(p());t.hidden=true;candidates.push(t);
  for(const candidate of candidates)
    assert.throws(()=>signOwnerPolicy(v,password,candidate,now));
});

test('strict vault formatting prevents oversized or malformed key material before derivation',()=>{
  const v=createEncryptedOwnerVault(password,new Date(now));
  const invalid=clone(v);invalid.salt_b64='****';
  assert.throws(()=>signOwnerPolicy(invalid,password,p(),now),/invalid_owner_vault/);
  const extra=clone(v);extra.UNTRUSTED='anything';
  assert.throws(()=>signOwnerPolicy(extra,password,p(),now),/invalid_owner_vault/);
  const bad=clone(v);bad.iv_b64='AAAA';
  assert.throws(()=>signOwnerPolicy(bad,password,p(),now),/invalid_owner_vault/);
});

test('signed grants contain no private key or passphrase and disabled capability remains disabled',()=>{
  const v=createEncryptedOwnerVault(password,new Date(now));
  const result=signOwnerPolicy(v,password,p(false),now);
  assert.equal(verifyOwnerBundle(result),true);
  assert.equal(result.owner_policy_json.includes('"enabled":false'),true);
  assert.equal(JSON.stringify(result).includes(v.ciphertext_b64),false);
  assert.equal(JSON.stringify(result).includes(password),false);
});
