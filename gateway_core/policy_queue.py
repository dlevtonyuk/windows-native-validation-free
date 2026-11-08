"""Portable, non-networked gateway core. NOT a production server or shell executor.

Authentication, TLS, secret storage and user-only installation/activation must be
implemented and verified by the deploying host. This module has no remote API.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import hmac
import json
import re
import sqlite3
import threading
from typing import Any, Callable

_ID = re.compile(r"^[a-z][a-z0-9_-]{2,63}$")
_ALLOWED = {"queued", "waiting_for_device", "succeeded", "failed"}

def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _parse_utc(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("invalid UTC timestamp")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None or result.utcoffset().total_seconds() != 0:
        raise ValueError("UTC timestamp required")
    return result

def _identifier(name: str) -> str:
    if not isinstance(name, str) or not _ID.fullmatch(name):
        raise ValueError("invalid identifier")
    return name

class Denied(PermissionError):
    """Requested action has not been owner-activated or is out of scope."""

class CapabilityPolicy:
    """Read-only verifier for a host-provisioned, owner-signed policy.

    No API for enabling capability is intentionally provided. The signing
    key MUST be stored outside the gateway transport and source repository.
    """

    def __init__(self, document: dict[str, Any] | None = None, signature: str | None = None,
                 owner_key: bytes | None = None):
        self._caps: dict[str, Any] = {}
        if document is None and signature is None:
            return  # DENY ALL
        if not isinstance(document, dict) or not isinstance(owner_key, bytes) or len(owner_key) < 32:
            raise Denied("missing host-provisioned owner policy/key")
        if not isinstance(signature, str) or not re.fullmatch(r"[0-9a-f]{64}", signature):
            raise Denied("invalid policy signature")
        expected = hmac.new(owner_key, _canonical(document), sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise Denied("policy signature verification failed")
        if set(document) != {"version", "owner", "expires_utc", "capabilities"}:
            raise Denied("unexpected policy fields")
        if document["version"] != 1 or document["owner"] != "local_owner":
            raise Denied("unsupported policy version or owner")
        if _parse_utc(document["expires_utc"]) <= _utcnow():
            raise Denied("signed policy expired")
        caps = document["capabilities"]
        if not isinstance(caps, dict):
            raise Denied("invalid capability set")
        for name, entry in caps.items():
            _identifier(name)
            if not isinstance(entry, dict) or set(entry) != {"enabled", "operations", "devices"}:
                raise Denied("invalid capability entry")
            if not isinstance(entry["enabled"], bool):
                raise Denied("invalid activation state")
            for field in ("operations", "devices"):
                vals = entry[field]
                if not isinstance(vals, list) or len(vals) > 64 or len(set(vals)) != len(vals):
                    raise Denied("invalid capability scope")
                for item in vals:
                    _identifier(item)
        self._caps = caps

    def permits(self, capability: str, operation: str, device: str) -> bool:
        for x in (capability, operation, device):
            _identifier(x)
        spec = self._caps.get(capability)
        return bool(spec and spec["enabled"] is True and
                    operation in spec["operations"] and device in spec["devices"])

@dataclass(frozen=True)
class Command:
    job_id: str
    capability: str
    operation: str
    device: str
    payload: dict[str, Any]

    def validate(self) -> None:
        for value in (self.job_id, self.capability, self.operation, self.device):
            _identifier(value)
        if not isinstance(self.payload, dict) or len(_canonical(self.payload)) > 4096:
            raise ValueError("invalid payload or payload too large")

class Gateway:
    """Portable queue/authorization state engine; not a network listener.

    The embedding transport must authenticate requester and apply TLS.
    Handler registry must be provisioned by trusted host deployment, never
    from incoming requests. No dynamic subprocess or shell action exists.
    """

    def __init__(self, db_path: str, policy: CapabilityPolicy | None = None):
        self.policy = policy or CapabilityPolicy()
        self._mutex = threading.RLock()
        self._db = sqlite3.connect(db_path, check_same_thread=False)
        self._db.execute("PRAGMA busy_timeout=5000")
        self._db.execute("""CREATE TABLE IF NOT EXISTS jobs (
            job_id TEXT PRIMARY KEY, capability TEXT NOT NULL,
            operation TEXT NOT NULL, device TEXT NOT NULL,
            payload_json TEXT NOT NULL, state TEXT NOT NULL,
            result_json TEXT, created_utc TEXT NOT NULL)""")
        self._db.execute("""CREATE TABLE IF NOT EXISTS audit (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            event_json TEXT NOT NULL, previous_hash TEXT NOT NULL,
            digest TEXT NOT NULL)""")
        self._db.commit()
        self._handlers: dict[tuple[str, str], Callable[[dict[str, Any]], Any]] = {}

    def close(self) -> None:
        with self._mutex:
            self._db.close()

    def register_handler(self, capability: str, operation: str,
                         handler: Callable[[dict[str, Any]], Any]) -> None:
        _identifier(capability)
        _identifier(operation)
        if not callable(handler):
            raise TypeError("trusted handler required")
        key = (capability, operation)
        if key in self._handlers:
            raise ValueError("handler already registered")
        self._handlers[key] = handler

    def _audit(self, event: str, job: str, detail: str) -> None:
        previous_row = self._db.execute("SELECT digest FROM audit ORDER BY sequence DESC LIMIT 1").fetchone()
        previous = previous_row[0] if previous_row else "0" * 64
        # Never log payloads, credentials or handler output.
        item = _canonical({"utc": _utcnow().isoformat(), "event": event,
                           "job_id": job, "detail": detail})
        digest = sha256(previous.encode("ascii") + item).hexdigest()
        self._db.execute("INSERT INTO audit(event_json,previous_hash,digest) VALUES (?,?,?)",
                         (item.decode("ascii"), previous, digest))
        self._db.commit()

    def submit(self, command: Command) -> str:
        command.validate()
        with self._mutex:
            if not self.policy.permits(command.capability, command.operation, command.device):
                self._audit("denied", command.job_id, "capability_not_activated_or_out_of_scope")
                raise Denied("owner has not activated this exact capability/operation/device")
            if (command.capability, command.operation) not in self._handlers:
                self._audit("denied", command.job_id, "handler_not_registered")
                raise Denied("no trusted local handler registered")
            data = _canonical(command.payload).decode("ascii")
            with self._db:
                try:
                    self._db.execute(
                        "INSERT INTO jobs(job_id,capability,operation,device,payload_json,state,created_utc) "
                        "VALUES (?,?,?,?,?,?,?)",
                        (command.job_id, command.capability, command.operation, command.device,
                         data, "queued", _utcnow().isoformat()))
                except sqlite3.IntegrityError as ex:
                    raise Denied("duplicate job_id (replay prevented)") from ex
            self._audit("submitted", command.job_id, "queued")
            return "queued"

    def execute(self, job_id: str, *, device_online: bool) -> str:
        _identifier(job_id)
        if not isinstance(device_online, bool):
            raise ValueError("trusted device-online state required")
        with self._mutex:
            row = self._db.execute("SELECT capability,operation,device,payload_json,state "
                                   "FROM jobs WHERE job_id=?", (job_id,)).fetchone()
            if row is None:
                raise KeyError("unknown job")
            capability, operation, device, payload_json, state = row
            if state not in ("queued", "waiting_for_device"):
                raise Denied("job already completed or failed")
            if not self.policy.permits(capability, operation, device):
                self._audit("denied", job_id, "policy_revoked_or_expired")
                raise Denied("capability no longer permitted")
            if not device_online:
                self._db.execute("UPDATE jobs SET state=? WHERE job_id=?",
                                 ("waiting_for_device", job_id))
                self._db.commit()
                self._audit("waiting", job_id, "device_offline")
                return "waiting_for_device"
            handler = self._handlers.get((capability, operation))
            if handler is None:
                raise Denied("handler disappeared")
            # This is intentionally not an arbitrary command or subprocess runner.
            # Host-specific handlers must implement their own bounded execution.
            try:
                output = handler(json.loads(payload_json))
                result_json = _canonical(output).decode("ascii")
                if len(result_json) > 4096:
                    raise ValueError("handler result too large")
                newstate = "succeeded"
            except Exception:
                result_json = None
                newstate = "failed"
            self._db.execute("UPDATE jobs SET state=?, result_json=? WHERE job_id=?",
                             (newstate, result_json, job_id))
            self._db.commit()
            self._audit("completed", job_id, newstate)
            return newstate

    def state(self, job_id: str) -> str:
        _identifier(job_id)
        row = self._db.execute("SELECT state FROM jobs WHERE job_id=?", (job_id,)).fetchone()
        if row is None:
            raise KeyError(job_id)
        return row[0]

    def audit_verified(self) -> bool:
        prev = "0" * 64
        for event, predecessor, digest in self._db.execute(
                "SELECT event_json,previous_hash,digest FROM audit ORDER BY sequence"):
            if predecessor != prev or sha256(prev.encode("ascii") + event.encode("ascii")).hexdigest() != digest:
                return False
            prev = digest
        return True
