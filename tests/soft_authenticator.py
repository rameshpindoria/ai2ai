"""A software WebAuthn authenticator (P-256, 'none' attestation) for offline tests. It produces real
registration and assertion structures that the `webauthn` library verifies, plus knobs to make bad ones."""
import base64
import hashlib
import json
import os
import struct

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

UP, UV, AT = 0x01, 0x04, 0x40


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class SoftAuthenticator:
    def __init__(self, user: str = "approver@demo-customer.example"):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = os.urandom(16)
        self.user = user.encode()
        self.counter = 0

    def _cose(self) -> bytes:
        n = self.key.public_key().public_numbers()
        return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})

    def register(self, options_json: str, origin: str) -> dict:
        o = json.loads(options_json)
        rp_id = o["rp"]["id"]
        client_data = json.dumps({"type": "webauthn.create", "challenge": o["challenge"], "origin": origin,
                                  "crossOrigin": False}).encode()
        auth_data = (hashlib.sha256(rp_id.encode()).digest() + bytes([UP | UV | AT]) + struct.pack(">I", 0)
                     + b"\x00" * 16 + struct.pack(">H", len(self.cred_id)) + self.cred_id + self._cose())
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": b64u(client_data), "attestationObject": b64u(att)},
                "clientExtensionResults": {}}

    def assert_(self, options_json: str, origin: str, *, uv: bool = True, rp_id: str = None,
                counter: int = None, challenge: str = None) -> dict:
        o = json.loads(options_json)
        rp = rp_id or o["rpId"]
        if counter is None:
            self.counter += 1
            counter = self.counter
        client_data = json.dumps({"type": "webauthn.get", "challenge": challenge or o["challenge"], "origin": origin,
                                  "crossOrigin": False}).encode()
        auth_data = hashlib.sha256(rp.encode()).digest() + bytes([UP | (UV if uv else 0)]) + struct.pack(">I", counter)
        sig = self.key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": b64u(client_data), "authenticatorData": b64u(auth_data),
                             "signature": b64u(sig), "userHandle": b64u(self.user)},
                "clientExtensionResults": {}}
