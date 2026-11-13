"""Offline signed-owner policy verification; read-only to execution processes."""
import base64
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

AUDIENCE = "universal-automation-gateway"


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


class PolicyError(Exception):
    pass


class OwnerPolicy:
    def __init__(self, policy_path, pinned_public_key):
        self.path = Path(policy_path)
        self.pinned_public_key = bytes(pinned_public_key)
        if len(self.pinned_public_key) != 32:
            raise ValueError("An Ed25519 public key must be 32 bytes")

    def load(self, now=None, allow_expired=False):
        now = now or datetime.now(timezone.utc)
        try:
            envelope = json.loads(self.path.read_text(encoding="utf-8"))
            if set(envelope) != {"policy", "signature"}:
                raise PolicyError("Signed envelope schema invalid")
            policy = envelope["policy"]
            signature = base64.b64decode(envelope["signature"], validate=True)
            Ed25519PublicKey.from_public_bytes(self.pinned_public_key).verify(signature, canonical(policy))
            if not isinstance(policy, dict) or policy.get("audience") != AUDIENCE:
                raise PolicyError("Wrong policy audience")
            if type(policy.get("revision")) is not int or policy["revision"] < 1:
                raise PolicyError("Policy revision invalid")
            if type(policy.get("global_stop")) is not bool:
                raise PolicyError("Global stop field missing or invalid")
            until = datetime.fromisoformat(policy["expires_at"].replace("Z", "+00:00"))
            if until.tzinfo is None or (not allow_expired and now >= until):
                raise PolicyError("Expired or timezone-free policy")
            if not isinstance(policy.get("capabilities"), dict):
                raise PolicyError("Capability map invalid")
            for name, rule in policy["capabilities"].items():
                if not isinstance(name, str) or not isinstance(rule, dict) or type(rule.get("enabled")) is not bool:
                    raise PolicyError("Capability rule invalid")
                for key in ("actors", "devices", "environments"):
                    arr = rule.get(key)
                    if not isinstance(arr, list) or not arr or any(not isinstance(s, str) or not s for s in arr):
                        raise PolicyError("Capability scopes invalid")
            return policy
        except PolicyError:
            raise
        except (OSError, ValueError, KeyError, TypeError, InvalidSignature) as exc:
            raise PolicyError("Owner policy missing, malformed or signature-invalid") from exc


def can_use(policy, capability, identity):
    if policy.get("global_stop", True):
        raise PermissionError("Owner emergency stop is active")
    rule = policy["capabilities"].get(capability)
    if not rule or rule.get("enabled") is not True:
        raise PermissionError("Owner has not enabled this capability")
    for field, plural in (("actor", "actors"), ("device", "devices"), ("environment", "environments")):
        if identity[field] not in rule[plural] and "*" not in rule[plural]:
            raise PermissionError("Scope not granted: " + plural)
    return policy["revision"]
