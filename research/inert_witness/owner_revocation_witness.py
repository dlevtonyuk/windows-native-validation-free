"""OFFLINE research monotonic witness. No live provider or external effects.

The witness database and witness private signing key are a distinct trust domain IN DESIGN;
in this fixture both run on one disposable machine and do not attest independence.
"""
import base64
import hashlib
import json
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from uag.policy import canonical

SCHEMA='uag.external-revision-witness.v1'
RESERVATION_SCHEMA='uag.external-witness-reservation.v1'
STATUS_SCHEMA='uag.external-witness-status.v1'

class WitnessDenied(Exception):pass

def verify(public,signature,message):
    try:Ed25519PublicKey.from_public_bytes(public).verify(signature,canonical(message))
    except (TypeError,ValueError,InvalidSignature) as e:raise WitnessDenied('invalid_signature') from e

def h(x):return hashlib.sha256(x).hexdigest()

def typed_int(x):return type(x) is int and 0<=x<2**53

class ExternalMonotonicWitness:
    """Owner publishes updates here independently of coordinator DB resets."""
    def __init__(self,path,owner_public,witness_private,clock=time.time):
        self.path=str(path)
        self.owner_public=owner_public
        self.signer=witness_private
        self.clock=clock
        self.conn=sqlite3.connect(self.path,isolation_level=None,check_same_thread=False,timeout=5)
        self.conn.execute('PRAGMA journal_mode=WAL')
        self.conn.execute('PRAGMA synchronous=FULL')
        self.conn.executescript('''
        CREATE TABLE IF NOT EXISTS policy(id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL,digest TEXT NOT NULL,enabled INTEGER NOT NULL CHECK(enabled IN(0,1)));
        CREATE TABLE IF NOT EXISTS slots(slot INTEGER PRIMARY KEY,cue_digest TEXT NOT NULL,revision INTEGER NOT NULL,host_id TEXT NOT NULL,receipt_digest TEXT NOT NULL);
        ''')
        self.lock=threading.RLock()
        self.available=True
    def close(self):
        with self.lock:self.conn.close()
    def _available(self):
        if not self.available:raise WitnessDenied('witness_unavailable')
    def _begin(self):self.conn.execute('BEGIN IMMEDIATE')
    def publish_owner(self,policy,signature):
        self._available()
        if (type(policy) is not dict or set(policy)!={'schema','revision','enabled'} or
            policy['schema']!='uag.distributed-inert-policy.v1' or
            not typed_int(policy['revision']) or policy['revision']==0 or
            type(policy['enabled']) is not bool):raise WitnessDenied('invalid_owner_policy')
        verify(self.owner_public,signature,policy)
        digest=h(canonical(policy))
        with self.lock:
            self._begin()
            try:
                old=self.conn.execute('SELECT revision,digest FROM policy WHERE id=1').fetchone()
                if old and (policy['revision']<old[0] or policy['revision']==old[0] and digest!=old[1]):
                    raise WitnessDenied('witness_rollback_or_fork')
                if old is None or policy['revision']>old[0]:
                    self.conn.execute('INSERT INTO policy(id,revision,digest,enabled) VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,digest=excluded.digest,enabled=excluded.enabled',
                        (policy['revision'],digest,int(policy['enabled'])))
                self.conn.execute('COMMIT')
                return 'published'
            except BaseException:
                self.conn.execute('ROLLBACK');raise
    def current(self):
        self._available()
        with self.lock:
            r=self.conn.execute('SELECT revision,digest,enabled FROM policy WHERE id=1').fetchone()
        if not r:raise WitnessDenied('unconfigured')
        return {'revision':r[0],'digest':r[1],'enabled':bool(r[2])}
    def reserve(self,slot,cue_digest,revision,host_id,expected_digest):
        self._available()
        if (not typed_int(slot) or not typed_int(revision) or
            type(host_id) is not str or not 3<=len(host_id)<=32 or
            type(cue_digest) is not str or len(cue_digest)!=64 or
            type(expected_digest) is not str or len(expected_digest)!=64):raise WitnessDenied('invalid_claim')
        with self.lock:
            self._begin()
            try:
                r=self.conn.execute('SELECT revision,digest,enabled FROM policy WHERE id=1').fetchone()
                if not r or r!=(revision,expected_digest,1):raise WitnessDenied('owner_witness_denied')
                old=self.conn.execute('SELECT slot FROM slots WHERE slot=?',(slot,)).fetchone()
                if old:raise WitnessDenied('already_seen_by_witness')
                payload={'schema':RESERVATION_SCHEMA,'slot':slot,'cue_sha256':cue_digest,
                         'revision':revision,'owner_policy_digest':expected_digest,'host_id':host_id}
                digest=h(canonical(payload))
                self.conn.execute('INSERT INTO slots VALUES(?,?,?,?,?)',(slot,cue_digest,revision,host_id,digest))
                self.conn.execute('COMMIT')
                return {'payload':payload,'signature_b64':base64.b64encode(self.signer.sign(canonical(payload))).decode('ascii')}
            except BaseException:
                self.conn.execute('ROLLBACK');raise
    def attest_current(self,nonce):
        self._available()
        if type(nonce) is not str or len(nonce)!=48 or any(c not in '0123456789abcdef' for c in nonce):raise WitnessDenied('bad_nonce')
        with self.lock:
            p=self.current()
            payload={'schema':STATUS_SCHEMA,'nonce':nonce,'issued_at':int(self.clock()),**p}
            return {'payload':payload,'signature_b64':base64.b64encode(self.signer.sign(canonical(payload))).decode('ascii')}
    def slot(self,slot):
        self._available()
        with self.lock:
            r=self.conn.execute('SELECT cue_digest,revision,host_id,receipt_digest FROM slots WHERE slot=?',(slot,)).fetchone()
            return r

class IndependentHostWitnessVerifier:
    """The host independently pins witness public key and checks latest state.
    No coordinator-issued 'approved' Boolean is ever accepted as proof.
    """
    def __init__(self,witness,witness_public,clock=time.time):
        self.witness=witness
        self.witness_public=witness_public
        self.clock=clock
    def authorize_inert_effect(self,receipt,slot,cue_digest,revision,host_id,owner_policy_digest):
        try:
            if not isinstance(receipt,dict) or set(receipt)!={'payload','signature_b64'}:
                raise WitnessDenied('receipt_shape')
            p=receipt['payload']
            if not isinstance(p,dict) or set(p)!={'schema','slot','cue_sha256','revision','owner_policy_digest','host_id'}:
                raise WitnessDenied('receipt_payload')
            signature=base64.b64decode(receipt['signature_b64'],validate=True)
            verify(self.witness_public,signature,p)
            expected={'schema':RESERVATION_SCHEMA,'slot':slot,'cue_sha256':cue_digest,'revision':revision,
                      'owner_policy_digest':owner_policy_digest,'host_id':host_id}
            if p!=expected:raise WitnessDenied('receipt_scope')
            nonce=secrets.token_hex(24)
            att=self.witness.attest_current(nonce)
            a=att['payload']
            verify(self.witness_public,base64.b64decode(att['signature_b64'],validate=True),a)
            if (not isinstance(a,dict) or set(a)!={'schema','nonce','issued_at','revision','digest','enabled'} or
                a['schema']!=STATUS_SCHEMA or a['nonce']!=nonce or
                not typed_int(a['issued_at']) or abs(self.clock()-a['issued_at'])>5 or
                a['revision']!=revision or a['digest']!=owner_policy_digest or a['enabled'] is not True):
                raise WitnessDenied('stale_or_revoked')
            slotrow=self.witness.slot(slot)
            if not slotrow or slotrow!=(cue_digest,revision,host_id,h(canonical(p))):
                raise WitnessDenied('not_registered')
            return True
        except (ValueError,TypeError,KeyError,sqlite3.Error,WitnessDenied) as e:
            raise WitnessDenied('effect_denied') from e
