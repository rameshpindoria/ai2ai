"""Ed25519 signing over canonical JSON (ported from the POC), plus key export/import for persistence."""
import base64
import hashlib
import json
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

KID_LABELS = {"centre", "provider-org", "provider-agent", "provider-technician", "customer-idp", "customer-approver",
              "customer-broker", "test"}


class SignatureError(Exception):
    pass


def canonical(obj) -> bytes:
    """Deterministic JSON (sorted keys, no whitespace): a JCS-compatible form for the value types we sign."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(obj) -> str:
    return sha256(canonical(obj))


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def new_nonce() -> str:
    return b64u(os.urandom(12))


def kid_for(label: str, public_bytes: bytes) -> str:
    """Key ids are derived from the public key, so a party cannot claim someone else's kid."""
    if label not in KID_LABELS:
        raise ValueError(f"unknown key label {label}")
    return f"{label}:{sha256(public_bytes)[:16]}"


class Signer:
    def __init__(self, label: str, private: Ed25519PrivateKey = None):
        self.label = label
        self._sk = private or Ed25519PrivateKey.generate()
        self.public_bytes = self._sk.public_key().public_bytes(serialization.Encoding.Raw,
                                                               serialization.PublicFormat.Raw)
        self.kid = kid_for(label, self.public_bytes)

    @property
    def public_b64(self) -> str:
        return b64u(self.public_bytes)

    def sign(self, payload) -> dict:
        return {"payload": payload, "kid": self.kid, "sig": b64u(self._sk.sign(canonical(payload)))}

    def sign_bytes(self, data: bytes) -> str:
        return b64u(self._sk.sign(data))

    def private_bytes(self) -> bytes:
        return self._sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                      serialization.NoEncryption())

    @classmethod
    def from_private_bytes(cls, label: str, raw: bytes) -> "Signer":
        return cls(label, Ed25519PrivateKey.from_private_bytes(raw))


def verify_with_public(envelope: dict, public_b64: str, expected_kid: str = None) -> dict:
    """Verify an envelope against a known public key. Returns the payload or raises SignatureError."""
    if not isinstance(envelope, dict) or not {"payload", "kid", "sig"} <= envelope.keys():
        raise SignatureError("malformed envelope")
    if expected_kid is not None and envelope["kid"] != expected_kid:
        raise SignatureError(f"signed by {envelope['kid']}, expected {expected_kid}")
    try:
        raw = unb64u(public_b64)
        label = envelope["kid"].split(":", 1)[0]
        if kid_for(label, raw) != envelope["kid"]:
            raise SignatureError("key id does not match the public key")
        Ed25519PublicKey.from_public_bytes(raw).verify(unb64u(envelope["sig"]), canonical(envelope["payload"]))
    except (InvalidSignature, ValueError) as exc:
        raise SignatureError("bad signature") from exc
    return envelope["payload"]
