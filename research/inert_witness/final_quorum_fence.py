"""Offline additive effect-release check; retains immutable dual-witness predecessor.

Addresses one specific time-of-check/time-of-use window: revocation of witness A
between its irreversible effect permit and witness B's permit. This is NOT a
linearizable revocation guarantee, and can never undo an effect already started.
"""
import base64
import secrets
from dual_witness_fence import DualWitnessEffectFence, DualWitnessDenied
from owner_revocation_witness import STATUS_SCHEMA, typed_int, verify

class FinalQuorumFence(DualWitnessEffectFence):
    """Consume pre-effect authorizations, then freshly re-attest BOTH witnesses.

    The predecessor has already durably consumed the host slot by the time the
    final quorum begins. Any failed check forfeits the slot (quarantine). Never
    auto-retry. Host must only start the inert effect AFTER this method returns.
    """
    def authorize_inert_effect(self,reservations,slot,cue_digest,revision,host_id,owner_policy_digest):
        super().authorize_inert_effect(reservations,slot,cue_digest,revision,host_id,owner_policy_digest)
        for name in ('witness-a','witness-b'):
            try:
                nonce=secrets.token_hex(24)
                response=self.witnesses[name].attest_current(nonce)
                if type(response) is not dict or set(response)!={'payload','signature_b64'}:
                    raise DualWitnessDenied('status_container')
                payload=response['payload']
                if type(payload) is not dict or set(payload)!={'schema','nonce','issued_at','revision','digest','enabled'}:
                    raise DualWitnessDenied('status_shape')
                raw=base64.b64decode(response['signature_b64'],validate=True)
                verify(self.keys[name],raw,payload)
                if (payload['schema']!=STATUS_SCHEMA or payload['nonce']!=nonce or
                    not typed_int(payload['issued_at']) or abs(self.clock()-payload['issued_at'])>5 or
                    payload['revision']!=revision or payload['digest']!=owner_policy_digest or
                    payload['enabled'] is not True):
                    raise DualWitnessDenied('fresh_quorum_rejected')
            except Exception as exc:
                raise DualWitnessDenied('fresh_quorum_denied_quarantine') from exc
        # Another concurrent revocation could occur immediately after this
        # final recheck. Such a race requires owner-reviewed revocation semantics
        # and effect-side enforcement; do not claim zero revocation latency.
        return True
