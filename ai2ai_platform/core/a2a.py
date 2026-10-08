"""A2A v1.0.1 wire format (ported from the POC, checked against a2aproject/A2A tag v1.0.1).

- Agent Card: proto3 JSON field names; REQUIRED fields from a2a.proto; JWS signature per spec section 8.4:
  protected header {alg: EdDSA, typ: JOSE, kid}, payload = canonical card WITHOUT `signatures`,
  signing input = b64u(protected) "." b64u(payload).
- Task states TASK_STATE_*, guarded transitions; JSON-RPC error codes from spec section 5.4."""
import json
import time

from .crypto import SignatureError, b64u, canonical, unb64u

A2A_VERSION = "1.0"
EXTENSION_URI = "https://ai2ai.example/extensions/secure-profile/v1"
TASK_NOT_FOUND, TASK_NOT_CANCELABLE, UNSUPPORTED_OPERATION = -32001, -32002, -32004
EXTENSION_REQUIRED, VERSION_NOT_SUPPORTED = -32008, -32009
INVALID_PARAMS, METHOD_NOT_FOUND, INVALID_REQUEST = -32602, -32601, -32600

TERMINAL = {"TASK_STATE_COMPLETED", "TASK_STATE_FAILED", "TASK_STATE_CANCELED", "TASK_STATE_REJECTED"}
INTERRUPTED = {"TASK_STATE_INPUT_REQUIRED", "TASK_STATE_AUTH_REQUIRED"}
ALLOWED = {
    None: {"TASK_STATE_SUBMITTED", "TASK_STATE_REJECTED"},
    "TASK_STATE_SUBMITTED": {"TASK_STATE_WORKING", "TASK_STATE_CANCELED", "TASK_STATE_REJECTED", "TASK_STATE_FAILED"},
    "TASK_STATE_WORKING": {"TASK_STATE_INPUT_REQUIRED", "TASK_STATE_AUTH_REQUIRED", "TASK_STATE_COMPLETED",
                           "TASK_STATE_FAILED", "TASK_STATE_CANCELED"},
    "TASK_STATE_INPUT_REQUIRED": {"TASK_STATE_WORKING", "TASK_STATE_CANCELED", "TASK_STATE_FAILED"},
    "TASK_STATE_AUTH_REQUIRED": {"TASK_STATE_WORKING", "TASK_STATE_CANCELED", "TASK_STATE_FAILED"},
}
CARD_REQUIRED = ["name", "description", "supportedInterfaces", "version", "capabilities", "defaultInputModes",
                 "defaultOutputModes", "skills"]
INTERFACE_REQUIRED = ["url", "protocolBinding", "protocolVersion"]
SKILL_REQUIRED = ["id", "name", "description", "tags"]


class IllegalTransition(Exception):
    pass


class TaskStateMachine:
    def __init__(self):
        self.state, self.history = None, []

    def move(self, new: str):
        if new == self.state:
            return
        if new not in ALLOWED.get(self.state, set()):
            raise IllegalTransition(f"{self.state} -> {new} is not allowed")
        self.state = new
        self.history.append((new, time.time()))


def card_from_listing(bundle: dict, a2a_url: str, extension_params: dict = None) -> dict:
    """Build an A2A Agent Card from an AI2AI listing bundle (provider-signed card + centre countersignature)."""
    card = bundle["card"]["payload"]
    cs = bundle["countersig"]["payload"]
    cats = card["capabilities"]["categories"]
    return {
        "name": card["name"], "description": card["description"],
        "supportedInterfaces": [{"url": a2a_url, "protocolBinding": "JSONRPC", "protocolVersion": A2A_VERSION}],
        "provider": {"organization": cs["org_name"], "url": f"https://ai2ai.example/providers/{cs['org_id']}"},
        "version": card["version"],
        "capabilities": {"streaming": False, "pushNotifications": False, "extendedAgentCard": False,
                         "extensions": [{"uri": EXTENSION_URI, "required": True,
                                         "description": "AI2AI Secure Profile: customer-signed Work Orders, passkey "
                                                        "approval per change, signed receipts, customer kill switch.",
                                         "params": dict({"agentId": cs["agent_id"], "agentKid": cs["agent_kid"],
                                                         "orgKid": cs["org_kid"], "maxLevel": card["capabilities"]["max_level"],
                                                         "connectors": card["capabilities"]["connectors"],
                                                         "buildDigest": card["build_digest"]}, **(extension_params or {}))}]},
        "defaultInputModes": ["application/json"], "defaultOutputModes": ["application/json", "text/plain"],
        "skills": [{"id": c, "name": c.split(".", 1)[1].replace("-", " ").title() + " support",
                    "description": f"{card['description']} ({c})", "tags": [c, card["capabilities"]["max_level"]]}
                   for c in cats],
    }


def _signing_input(card: dict, protected_b64: str) -> bytes:
    payload = {k: v for k, v in card.items() if k != "signatures"}
    return f"{protected_b64}.{b64u(canonical(payload))}".encode("ascii")


def sign_card(card: dict, signer) -> dict:
    protected = b64u(json.dumps({"alg": "EdDSA", "typ": "JOSE", "kid": signer.kid}, separators=(",", ":")).encode())
    out = dict(card)
    out["signatures"] = list(card.get("signatures", [])) + [
        {"protected": protected, "signature": signer.sign_bytes(_signing_input(card, protected))}]
    return out


def verify_card(card: dict, trusted: dict) -> dict:
    """trusted: {kid: public_key_b64}. Returns the protected header of the first valid trusted signature."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    for sig in card.get("signatures") or []:
        try:
            header = json.loads(unb64u(sig["protected"]))
        except Exception:
            continue
        pub = trusted.get(header.get("kid"))
        if header.get("alg") != "EdDSA" or pub is None:
            continue
        try:
            Ed25519PublicKey.from_public_bytes(unb64u(pub)).verify(unb64u(sig["signature"]),
                                                                   _signing_input(card, sig["protected"]))
            return header
        except (InvalidSignature, ValueError):
            raise SignatureError("card signature invalid")
    raise SignatureError("no valid signature from a trusted key")


def card_shape_errors(card: dict) -> list:
    errs = [f"missing {f}" for f in CARD_REQUIRED if f not in card]
    for i in card.get("supportedInterfaces", []):
        errs += [f"interface missing {f}" for f in INTERFACE_REQUIRED if f not in i]
    for s in card.get("skills", []):
        errs += [f"skill missing {f}" for f in SKILL_REQUIRED if f not in s]
    if not card.get("supportedInterfaces"):
        errs.append("supportedInterfaces empty")
    return errs


def rpc_error(mid, code, message, data=None):
    e = {"code": code, "message": message}
    if data:
        e["data"] = data
    return {"jsonrpc": "2.0", "id": mid, "error": e}
