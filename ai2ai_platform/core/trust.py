"""Verifying a provider's agent listing with only the centre's public key as the trust anchor.

Listing bundle = {card, countersig, credentials}
- card:        provider-signed (org key) agent card: name, version, agent_kid, build_digest, capabilities
- countersig:  centre-signed; binds card digest + the provider's PUBLIC keys + valid credential ids + expiry
- credentials: centre-signed verifiable credentials (ISO27001/SOC2/insurance...) about the provider org
An edge verifying this needs nothing but the centre public key and the current revocation list."""
import time

from .crypto import SignatureError, digest, verify_with_public

SECURITY_CREDS = {"ISO27001", "SOC2", "CyberEssentials"}
INSURANCE_CREDS = {"PIInsurance", "CyberInsurance"}
LEVEL_RANK = {"D1": 1, "D2": 2, "D3": 3}


def required_credentials_met(kinds: set) -> list:
    missing = []
    if not kinds & SECURITY_CREDS:
        missing.append("a security certification (ISO 27001, SOC 2 or Cyber Essentials)")
    if not kinds & INSURANCE_CREDS:
        missing.append("insurance (PI or cyber)")
    return missing


def verify_listing(bundle: dict, centre_pub_b64: str, centre_kid: str, revoked: set = frozenset(), now=None):
    """Returns (ok, reasons, facts). facts carries the verified keys/level/categories for the caller to use."""
    now = time.time() if now is None else now
    reasons, facts = [], {}
    try:
        cs = verify_with_public(bundle["countersig"], centre_pub_b64, expected_kid=centre_kid)
    except (SignatureError, KeyError, TypeError) as exc:
        return False, [f"centre countersignature invalid: {exc}"], facts
    if cs.get("type") != "ListingCountersignature":
        return False, ["not a listing countersignature"], facts
    if cs["card_digest"] != digest(bundle.get("card")):
        reasons.append("countersignature does not match this card")
    try:
        card = verify_with_public(bundle["card"], cs["org_public_key"], expected_kid=cs["org_kid"])
    except (SignatureError, KeyError) as exc:
        return False, reasons + [f"agent card not signed by the provider's registered key: {exc}"], facts
    if card.get("agent_kid") != cs.get("agent_kid"):
        reasons.append("card agent key differs from the registered agent key")
    if now > cs.get("expires", 0):
        reasons.append("listing expired; the centre must re-countersign")
    for item in (cs["agent_id"], cs["org_id"], cs["org_kid"], cs["agent_kid"]):
        if item in revoked:
            reasons.append(f"revoked: {item}")
    valid_kinds, valid_creds = set(), {}
    for cred_env in bundle.get("credentials", []):
        try:
            cred = verify_with_public(cred_env, centre_pub_b64, expected_kid=centre_kid)
        except SignatureError as exc:
            reasons.append(f"credential signature invalid: {exc}")
            continue
        if cred.get("subject_org") != cs["org_id"]:
            reasons.append("credential issued to a different provider")
        elif cred["id"] in revoked:
            reasons.append(f"{cred['credential_type']} credential revoked")
        elif cred["expires"] < now:
            reasons.append(f"{cred['credential_type']} credential expired")
        elif cred["id"] in cs.get("credential_ids", []):
            valid_kinds.add(cred["credential_type"])
            valid_creds[cred["id"]] = cred["credential_type"]
    reasons += [f"missing valid {m}" for m in required_credentials_met(valid_kinds)]
    facts = {"org_id": cs["org_id"], "org_name": cs["org_name"], "org_kid": cs["org_kid"],
             "org_public_key": cs["org_public_key"], "agent_id": cs["agent_id"], "agent_kid": cs["agent_kid"],
             "agent_public_key": cs["agent_public_key"], "max_level": card["capabilities"]["max_level"],
             "categories": card["capabilities"]["categories"], "connectors": card["capabilities"]["connectors"],
             "credential_kinds": sorted(valid_kinds), "credentials": valid_creds, "version": card["version"], "build_digest": card["build_digest"],
             "technician_keys": {k["kid"]: k["public_key"] for k in cs.get("technician_keys", [])
                                 if k["kid"] not in revoked}}
    return (not reasons), reasons, facts
