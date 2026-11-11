// OFFLINE OWNER SIGNING PROTOTYPE. No network calls, no file access, no deployment.
// Private owner keys must never be committed, uploaded, passed to an LLM, or
// generated in public CI for later production use. CI exercises throwaway keys.
import { randomBytes, generateKeyPairSync, createCipheriv, createDecipheriv,
  scryptSync, createPrivateKey, createPublicKey, sign, verify,
  timingSafeEqual } from 'node:crypto';

const CONTEXT='uag-owner-key-v1';
const SPKI_PREFIX=Buffer.from('302a300506032b6570032100','hex');
const ID=/^[a-z][a-z0-9_-]{2,63}$/;
const B64=/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const KDF=Object.freeze({N:16384,r:8,p:1,maxmem:67108864});
const MAX_AGE_MS=90*24*60*60*1000;
const b64=x=>Buffer.from(x).toString('base64');
function decB64(x,bytes){
  if(typeof x!=='string'||x.length>10000||!B64.test(x))throw Error('invalid_owner_vault');
  const out=Buffer.from(x,'base64');
  if(bytes!==undefined&&out.length!==bytes)throw Error('invalid_owner_vault');
  return out;
}
function derive(passphrase,salt){
  if(typeof passphrase!=='string'||passphrase.length<16||passphrase.length>4096)
    throw Error('invalid_passphrase');
  return scryptSync(passphrase,salt,32,KDF);
}
function rawPublicFromKey(key){
  const spki=createPublicKey(key).export({type:'spki',format:'der'});
  if(spki.length!==44 || !spki.subarray(0,12).equals(SPKI_PREFIX))
    throw Error('unexpected_public_key_format');
  return Buffer.from(spki.subarray(12));
}
function validatePolicy(p,nowMs){
  if(!p||typeof p!=='object'||Array.isArray(p)||
     Object.keys(p).sort().join(',')!=='capabilities,expires_utc,owner,revision,version'||
     p.version!==1||p.owner!=='local_owner'||!Number.isSafeInteger(p.revision)||
     p.revision<1||typeof p.expires_utc!=='string')
    throw Error('invalid_owner_policy');
  const expire=Date.parse(p.expires_utc);
  if(!Number.isFinite(expire)||expire<=nowMs||expire>nowMs+MAX_AGE_MS)
    throw Error('unsafe_policy_expiration');
  if(!p.capabilities||typeof p.capabilities!=='object'||Array.isArray(p.capabilities))
    throw Error('invalid_owner_policy');
  if(Object.keys(p.capabilities).length>32)throw Error('invalid_owner_policy');
  for(const [name,cap] of Object.entries(p.capabilities)){
    if(!ID.test(name)||!cap||typeof cap!=='object'||Array.isArray(cap)||
       Object.keys(cap).sort().join(',')!=='devices,enabled,operations'||
       typeof cap.enabled!=='boolean'||!Array.isArray(cap.operations)||!Array.isArray(cap.devices)||
       cap.operations.length>64||cap.devices.length>64||
       !cap.operations.every(x=>typeof x==='string'&&ID.test(x))||
       !cap.devices.every(x=>typeof x==='string'&&ID.test(x))||
       new Set(cap.operations).size!==cap.operations.length||
       new Set(cap.devices).size!==cap.devices.length)
      throw Error('invalid_owner_policy');
  }
  const str=JSON.stringify(p);
  if(Buffer.byteLength(str,'utf8')>4096)throw Error('owner_policy_too_large');
  return str;
}
function validateVault(v){
  if(!v||typeof v!=='object'||Array.isArray(v)||
     Object.keys(v).sort().join(',')!=='ciphertext_b64,created_utc,iv_b64,public_key_b64,salt_b64,tag_b64,version'||
     v.version!==CONTEXT||typeof v.created_utc!=='string'||
     !Number.isFinite(Date.parse(v.created_utc)))throw Error('invalid_owner_vault');
  const publicKey=decB64(v.public_key_b64,32);
  const salt=decB64(v.salt_b64,16);
  const iv=decB64(v.iv_b64,12);
  const tag=decB64(v.tag_b64,16);
  const ciphertext=decB64(v.ciphertext_b64);
  if(ciphertext.length<32||ciphertext.length>8192)throw Error('invalid_owner_vault');
  return {publicKey,salt,iv,tag,ciphertext};
}
export function createEncryptedOwnerVault(passphrase,createdAt=new Date()){
  const when=new Date(createdAt);
  if(!Number.isFinite(when.getTime()))throw Error('invalid_date');
  const {privateKey}=generateKeyPairSync('ed25519');
  const publicKey=rawPublicFromKey(privateKey);
  const salt=randomBytes(16),iv=randomBytes(12);
  const key=derive(passphrase,salt);
  const created=when.toISOString();
  const cipher=createCipheriv('aes-256-gcm',key,iv);
  cipher.setAAD(Buffer.from(CONTEXT+'|'+b64(publicKey)+'|'+created,'utf8'));
  const pkcs8=privateKey.export({format:'der',type:'pkcs8'});
  let enc;
  try{enc=Buffer.concat([cipher.update(pkcs8),cipher.final()]);}
  finally{pkcs8.fill(0);key.fill(0);}
  return {version:CONTEXT,created_utc:created,public_key_b64:b64(publicKey),
    salt_b64:b64(salt),iv_b64:b64(iv),tag_b64:b64(cipher.getAuthTag()),
    ciphertext_b64:b64(enc)};
}
export function signOwnerPolicy(vault,passphrase,policy,nowMs=Date.now()){
  const bytes=validateVault(vault);
  const payload=validatePolicy(policy,nowMs);
  const key=derive(passphrase,bytes.salt);
  const decipher=createDecipheriv('aes-256-gcm',key,bytes.iv);
  decipher.setAAD(Buffer.from(CONTEXT+'|'+vault.public_key_b64+'|'+vault.created_utc,'utf8'));
  decipher.setAuthTag(bytes.tag);
  let pkcs8;
  try{pkcs8=Buffer.concat([decipher.update(bytes.ciphertext),decipher.final()]);}
  catch{throw Error('owner_vault_decryption_failed');}
  finally{key.fill(0);}
  try{
    const privateKey=createPrivateKey({key:pkcs8,format:'der',type:'pkcs8'});
    const derived=rawPublicFromKey(privateKey);
    if(!timingSafeEqual(derived,bytes.publicKey))throw Error('owner_public_key_mismatch');
    return {owner_public_key_b64:vault.public_key_b64,
      owner_policy_json:payload,
      owner_policy_signature_b64:b64(sign(null,Buffer.from(payload,'utf8'),privateKey))};
  }finally{pkcs8?.fill(0);}
}
export function verifyOwnerBundle(bundle){
  if(!bundle||typeof bundle!=='object'||typeof bundle.owner_policy_json!=='string'||
     typeof bundle.owner_public_key_b64!=='string'||
     typeof bundle.owner_policy_signature_b64!=='string')return false;
  try{
    const raw=decB64(bundle.owner_public_key_b64,32);
    const signature=decB64(bundle.owner_policy_signature_b64,64);
    const spki=Buffer.concat([SPKI_PREFIX,raw]);
    return verify(null,Buffer.from(bundle.owner_policy_json,'utf8'),
      createPublicKey({key:spki,format:'der',type:'spki'}),signature);
  }catch{return false;}
}
