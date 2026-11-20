"""Research-only owner-private GitHub claim ledger for Workyard approvals.

Never used by an assistant-accessible repository with production credentials.
The trusted owner's private workflow MUST vendor/pin and review this module,
control its GitHub token, and independently protect approval policy, credentials,
source revisions and deployment identity. No default network transport exists.

A claim is committed and read back in the excluded private repository BEFORE an
approval attempt. Unknown GitHub outcomes consume or hold that timecard until
an owner-trusted reconciliation. This module has no Workyard network client.
"""
from __future__ import annotations
import base64
import hashlib
import json
import re
from dataclasses import dataclass


class Held(RuntimeError):
    """No Workyard effect may follow this error."""


def _int(n):
    return type(n) is int and 0 < n < 2**53


def _sha(s):
    return isinstance(s, str) and re.fullmatch(r"[a-f0-9]{64}", s) is not None


def _blob_hash(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


@dataclass(frozen=True)
class Intent:
    organization_id: int
    time_card_id: int
    expected_revision: int
    grant_sha256: str

    def validate(self):
        if not all(_int(x) for x in (self.organization_id, self.time_card_id, self.expected_revision)):
            raise Held("invalid_card_or_revision")
        if not _sha(self.grant_sha256):
            raise Held("invalid_grant_hash")

    @property
    def path(self):
        self.validate()
        return f".uag/workyard/claims/org_{self.organization_id}/time_card_{self.time_card_id}.json"

    def bytes(self):
        self.validate()
        return (json.dumps({"schema_version": 1, "organization_id": self.organization_id,
                            "time_card_id": self.time_card_id,
                            "expected_revision": self.expected_revision,
                            "grant_sha256": self.grant_sha256,
                            "state": "RESERVED_BEFORE_EFFECT"},
                           sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


class OwnerPrivateGithubLedger:
    """Requires injected trusted/private GitHub transport, never arbitrary URLs.

    request(method, path, json_body) -> (status:int, JSON dict). Request must
    authenticate ONLY to GitHub api.github.com with credentials owned by the
    protected owner repository. Fail closed on any error, even ambiguous writes.
    """
    def __init__(self, repository: str, branch: str, request):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
            raise Held("invalid_protected_repo")
        if branch != "main":
            raise Held("non_owner_default_branch")
        if not callable(request):
            raise Held("protected_transport_absent")
        self.repository = repository
        self.branch = branch
        self.request = request

    def _request(self, method, path, body=None):
        try:
            status, payload = self.request(method, path, body)
        except Exception:
            raise Held("private_ledger_transport_unknown") from None
        if type(status) is not int or not isinstance(payload, dict):
            raise Held("private_ledger_response_invalid")
        return status, payload

    def reserve(self, intent: Intent):
        intent.validate()
        path = f"/repos/{self.repository}/contents/{intent.path}"
        raw = intent.bytes()
        expected = _blob_hash(raw)
        body = {"message": "Reserve Workyard approval intent (no external effect)",
                "branch": self.branch,
                "content": base64.b64encode(raw).decode("ascii")}
        status, reply = self._request("PUT", path, body)
        if status != 201 or reply.get("content", {}).get("sha") != expected or not reply.get("commit", {}).get("sha"):
            raise Held("owner_claim_not_confirmed_or_duplicate")
        # Read back from owner-private main. No Workyard effects before this.
        status, verify = self._request("GET", path + "?ref=" + self.branch)
        if status != 200 or verify.get("sha") != expected:
            raise Held("owner_claim_readback_failed")
        encoded = verify.get("content")
        if not isinstance(encoded, str) or verify.get("encoding") != "base64":
            raise Held("owner_claim_content_unverified")
        try:
            check = base64.b64decode(encoded, validate=False)
        except Exception:
            raise Held("owner_claim_content_invalid") from None
        if check != raw:
            raise Held("owner_claim_content_mismatch")
        return {"reserved": True, "card_id": intent.time_card_id,
                "claim_sha": expected, "commit_sha": reply["commit"]["sha"]}

    def receipt(self, intent: Intent, outcome: str):
        # A receipt is evidence only; the original immutable claim is never removed.
        if outcome not in ("VERIFIED_APPROVED", "HELD_UNKNOWN", "HELD_PRE_EFFECT"):
            raise Held("invalid_receipt_outcome")
        path = f"/repos/{self.repository}/contents/.uag/workyard/receipts/org_{intent.organization_id}/time_card_{intent.time_card_id}.json"
        raw = (json.dumps({"schema_version": 1, "time_card_id": intent.time_card_id,
                           "grant_sha256": intent.grant_sha256, "outcome": outcome},
                          sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        expected = _blob_hash(raw)
        status, reply = self._request("PUT", path, {
            "message": "Record Workyard approval outcome (immutable claim retained)",
            "branch": self.branch,
            "content": base64.b64encode(raw).decode("ascii")})
        if status != 201 or reply.get("content", {}).get("sha") != expected or not reply.get("commit", {}).get("sha"):
            raise Held("receipt_not_confirmed")
        status, verify = self._request("GET", path + "?ref=" + self.branch)
        if status != 200 or verify.get("sha") != expected or verify.get("encoding") != "base64":
            raise Held("receipt_readback_failed")
        try:
            check = base64.b64decode(verify.get("content", ""), validate=False)
        except Exception:
            raise Held("receipt_content_invalid") from None
        if check != raw:
            raise Held("receipt_content_mismatch")
        return {"receipt_recorded": True, "receipt_sha": expected}


def attempt_approval(*, gate, ledger, intent: Intent):
    """Single-use adapter; owner-only gate must revalidate and decide approval.

    No retries under any circumstances. Callers MUST hold an exclusive per-org
    lock, and may only invoke through the trusted, owner-installed workflow.
    """
    intent.validate()
    first = gate.preflight(intent.time_card_id)
    if not isinstance(first, dict) or first.get("id") != intent.time_card_id or \
       first.get("updated_at_unix") != intent.expected_revision or \
       first.get("status") != "submitted":
        raise Held("source_revision_or_status_changed")
    # Mandatory durable reservation preceding Workyard PATCH.
    reserved = ledger.reserve(intent)
    if not reserved or reserved.get("reserved") is not True:
        raise Held("owner_claim_unverified")
    try:
        result = gate.approve(intent.time_card_id, intent.expected_revision)
    except Exception:
        try: ledger.receipt(intent, "HELD_UNKNOWN")
        except Exception: pass  # Original claim persists, no retries.
        raise Held("approval_held_reconcile_before_any_retry") from None
    if not isinstance(result, dict) or result.get("verified_approved") is not True or \
       result.get("time_card_id") != intent.time_card_id or result.get("status") != "approved":
        try: ledger.receipt(intent, "HELD_UNKNOWN")
        except Exception: pass
        raise Held("approval_readback_unverified")
    # A missing receipt doesn't convert verified Workyard success into safe retry.
    try: ledger.receipt(intent, "VERIFIED_APPROVED")
    except Exception: raise Held("approval_verified_but_receipt_unconfirmed_no_retry") from None
    return {"verified_approved": True, "card_id": intent.time_card_id,
            "claim_sha": reserved["claim_sha"]}