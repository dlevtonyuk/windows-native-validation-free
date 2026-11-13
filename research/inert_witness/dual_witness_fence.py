"""OFFLINE additive research. Dual keyed witnesses + host high-water state.

No network services, cloud resources, owner keys, real effects, or provider calls.
This model does not prove physical independence of the witness hosts.
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
from owner_revocation_witness import ExternalMonotonicWitness, WitnessDenied, verify, typed_int, h, RESERVATION_SCHEMA

DUAL_STATUS_SCHEMA='uag.dual-witness-claim-attestation.v1'

class DualWitnessDenied(Exception):pass

class SignedSlotWitness(ExternalMonotonicWitness):
    """Atomic snapshot of owner policy + exact slot, signed under per-witness key."""
    def __init__(self,path,owner_public,witness_private,witness_id,clock=time.time):
        if witness_id not in ('witness-a','witness-b'):
            raise ValueError('unrecognized_lab_witness')
        super().__init__(path,owner_public,witness_private,clock=clock)
        self.witness_id=witness_id
        self.conn.execute('CREATE TABLE IF NOT EXISTS effect_auth (slot INTEGER PRIMARY KEY, receipt_digest TEXT NOT NULL)')
    def authorize_once(self,nonce,slot,cue_digest,revision,host_id,owner_policy_digest):
        self._available()
        if (type(nonce) is not str or len(nonce)!=48 or any(c not in '0123456789abcdef' for c in nonce)
                or not typed_int(slot) or not typed_int(revision) or type(cue_digest) is not str or len(cue_digest)!=64
                or type(owner_policy_digest) is not str or len(owner_policy_digest)!=64
                or type(host_id) is not str or not 3<=len(host_id)<=32):
            raise WitnessDenied('bad_attestation_request')
        with self.lock:
            # A durable one-time effect permit, not repeatable read-only attestation.
            self.conn.execute('BEGIN IMMEDIATE')
            try:
                p=self.conn.execute('SELECT revision,digest,enabled FROM policy WHERE id=1').fetchone()
                s=self.conn.execute('SELECT cue_digest,revision,host_id,receipt_digest FROM slots WHERE slot=?',(slot,)).fetchone()
                expected_receipt={'schema':RESERVATION_SCHEMA,'slot':slot,'cue_sha256':cue_digest,
                    'revision':revision,'owner_policy_digest':owner_policy_digest,'host_id':host_id}
                receipt_digest=h(canonical(expected_receipt))
                if (p is None or p!=(revision,owner_policy_digest,1) or
                    s!=(cue_digest,revision,host_id,receipt_digest)):
                    raise WitnessDenied('owner_revoked_or_slot_mismatch')
                if self.conn.execute('SELECT 1 FROM effect_auth WHERE slot=?',(slot,)).fetchone():
                    raise WitnessDenied('effect_slot_already_consumed')
                payload={'schema':DUAL_STATUS_SCHEMA,'witness_id':self.witness_id,'nonce':nonce,
                    'issued_at':int(self.clock()),'slot':slot,'owner_revision':p[0],
                    'owner_digest':p[1],'enabled':bool(p[2]),
                    'claim':None if s is None else {
                        'cue_digest':s[0],'revision':s[1],'host_id':s[2],'receipt_digest':s[3]}}
                signed=base64.b64encode(self.signer.sign(canonical(payload))).decode('ascii')
                self.conn.execute('INSERT INTO effect_auth(slot,receipt_digest) VALUES (?,?)',(slot,receipt_digest))
                self.conn.execute('COMMIT')
            except BaseException:
                self.conn.execute('ROLLBACK');raise
            return {'payload':payload,'signature_b64':signed}

class HostHighWaterAnchor:
    """Protected-local *test* store. A production owner needs independent custody.

    Claims are consumed before synthetic effect; uncertain outcomes never replay.
    """
    def __init__(self,path,owner_public):
        self.path=str(path);self.owner_public=owner_public;self.lock=threading.RLock()
        self.conn=sqlite3.connect(self.path,isolation_level=None,timeout=5,check_same_thread=False)
        self.conn.execute('PRAGMA journal_mode=WAL')
        self.conn.execute('PRAGMA synchronous=FULL')
        self.conn.execute('CREATE TABLE IF NOT EXISTS floor (id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL, digest TEXT NOT NULL)')
        self.conn.execute('CREATE TABLE IF NOT EXISTS consumed (slot INTEGER PRIMARY KEY, receipt_digest TEXT NOT NULL)')
    def close(self):self.conn.close()
    def _commit(self,revision,digest,slot=None,receipt_digest=None):
        if (not typed_int(revision) or revision==0 or type(digest) is not str or len(digest)!=64):
            raise DualWitnessDenied('invalid_floor')
        with self.lock:
            self.conn.execute('BEGIN IMMEDIATE')
            try:
                old=self.conn.execute('SELECT revision,digest FROM floor WHERE id=1').fetchone()
                if old and (revision<old[0] or (revision==old[0] and digest!=old[1])):
                    raise DualWitnessDenied('host_detected_rollback_or_fork')
                if old is None or revision>old[0]:
                    self.conn.execute('INSERT INTO floor (id,revision,digest) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,digest=excluded.digest',(revision,digest))
                if slot is not None:
                    if not typed_int(slot) or type(receipt_digest) is not str or len(receipt_digest)!=64:
                        raise DualWitnessDenied('invalid_consumption')
                    try:self.conn.execute('INSERT INTO consumed(slot,receipt_digest) VALUES(?,?)',(slot,receipt_digest))
                    except sqlite3.IntegrityError as ex:raise DualWitnessDenied('host_slot_already_consumed') from ex
                self.conn.execute('COMMIT')
            except BaseException:
                self.conn.execute('ROLLBACK');raise
    def observe_owner_signed(self,policy,owner_signature):
        if not isinstance(policy,dict) or set(policy)!={'schema','revision','enabled'} or policy['schema']!='uag.distributed-inert-policy.v1' or type(policy['enabled']) is not bool:
            raise DualWitnessDenied('invalid_owner_policy')
        try:verify(self.owner_public,owner_signature,policy)
        except WitnessDenied as e:raise DualWitnessDenied('owner_signature_invalid') from e
        self._commit(policy['revision'],h(canonical(policy)))
    def floor(self):
        with self.lock:return self.conn.execute('SELECT revision,digest FROM floor WHERE id=1').fetchone()
    def consumed(self,slot):
        with self.lock:return self.conn.execute('SELECT receipt_digest FROM consumed WHERE slot=?',(slot,)).fetchone()
    def consume(self,revision,digest,slot,receipt_digest):self._commit(revision,digest,slot,receipt_digest)

class DualWitnessEffectFence:
    """Host-side verification. Never trusts a coordinator-supplied allow Boolean."""
    def __init__(self,witnesses,public_keys,host_anchor,clock=time.time):
        if (set(witnesses)!={'witness-a','witness-b'} or set(public_keys)!=set(witnesses)
              or witnesses['witness-a'] is witnesses['witness-b']
              or public_keys['witness-a']==public_keys['witness-b']):
            raise DualWitnessDenied('distinct_witnesses_required')
        self.witnesses=witnesses;self.keys=public_keys;self.anchor=host_anchor;self.clock=clock
    def reserve_two(self,slot,cue_digest,revision,host_id,owner_policy_digest):
        """Sequential irreversible pre-effect holds. Any partial result => quarantine.
        Receiver may not retry an uncertain result, even if a network response was lost.
        """
        receipts={}
        for name in ('witness-a','witness-b'):
            try:
                receipts[name]=self.witnesses[name].reserve(slot,cue_digest,revision,host_id,owner_policy_digest)
            except Exception as ex:
                raise DualWitnessDenied('partial_or_denied_reservation_quarantine') from ex
        return receipts
    def authorize_inert_effect(self,reservations,slot,cue_digest,revision,host_id,owner_policy_digest):
        if not isinstance(reservations,dict) or set(reservations)!={'witness-a','witness-b'}:
            raise DualWitnessDenied('missing_witness_reservation')
        if (not typed_int(slot) or not typed_int(revision) or type(cue_digest) is not str
           or len(cue_digest)!=64 or type(owner_policy_digest) is not str or len(owner_policy_digest)!=64
           or type(host_id) is not str or not (3<=len(host_id)<=32)):
            raise DualWitnessDenied('invalid_scope')
        p={'schema':RESERVATION_SCHEMA,'slot':slot,'cue_sha256':cue_digest,
           'revision':revision,'owner_policy_digest':owner_policy_digest,'host_id':host_id}
        receipt_digest=h(canonical(p))
        for name in ('witness-a','witness-b'):
            try:
                rec=reservations[name]
                if not isinstance(rec,dict) or set(rec)!={'payload','signature_b64'} or rec['payload']!=p:
                    raise DualWitnessDenied('reservation_mismatch')
                verify(self.keys[name],base64.b64decode(rec['signature_b64'],validate=True),p)
                nonce=secrets.token_hex(24)
                att=self.witnesses[name].authorize_once(nonce,slot,cue_digest,revision,host_id,owner_policy_digest)
                if not isinstance(att,dict) or set(att)!={'payload','signature_b64'}:
                    raise DualWitnessDenied('attestation_shape')
                q=att['payload']
                verify(self.keys[name],base64.b64decode(att['signature_b64'],validate=True),q)
                if not isinstance(q,dict) or set(q)!={'schema','witness_id','nonce','issued_at','slot','owner_revision','owner_digest','enabled','claim'}:
                    raise DualWitnessDenied('attestation_fields')
                if (q['schema']!=DUAL_STATUS_SCHEMA or q['witness_id']!=name or q['nonce']!=nonce
                    or not typed_int(q['issued_at']) or abs(self.clock()-q['issued_at'])>5 or
                    q['slot']!=slot or q['owner_revision']!=revision or
                    q['owner_digest']!=owner_policy_digest or q['enabled'] is not True or
                    q['claim']!={'cue_digest':cue_digest,'revision':revision,
                                 'host_id':host_id,'receipt_digest':receipt_digest}):
                    raise DualWitnessDenied('stale_revoked_or_wrong_claim')
            except Exception as ex:
                raise DualWitnessDenied('witness_validation_denied') from ex
        # Persistent host record is committed BEFORE any effect is released.
        # A crash here can forfeit an allowed synthetic job; it must not replay.
        self.anchor.consume(revision,owner_policy_digest,slot,receipt_digest)
        return True
