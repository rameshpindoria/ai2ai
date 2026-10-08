"""M2: provider onboarding, admin verification, credentials, signed agent listings, catalogue, revocation."""
import hashlib

from sqlalchemy import text

from ai2ai_platform.core.crypto import Signer, b64u
from ai2ai_platform.core.trust import verify_listing

AGENT_BUILD = hashlib.sha256(b"provider-a-agent-build-1.0.0").hexdigest()


class ProviderKit:
    """Plays the provider's own runtime: it generates and KEEPS its private keys; only public keys go to the centre."""

    def __init__(self, actor):
        self.a = actor
        self.org_key = Signer("provider-org")
        self.agent_key = Signer("provider-agent")

    def onboard(self, evidence=("ISO27001", "PIInsurance"), submit=True):
        assert self.a.post("/api/v1/provider/keys", json={"purpose": "org", "public_key": self.org_key.public_b64}).status_code == 201
        assert self.a.post("/api/v1/provider/keys", json={"purpose": "agent", "public_key": self.agent_key.public_b64}).status_code == 201
        for kind in evidence:
            r = self.a.post("/api/v1/provider/evidence", json={"kind": kind, "reference": f"{kind}-123",
                                                                "issuer": "Example Certifier", "expires_on": "2030-01-01"})
            assert r.status_code == 201, r.text
        if submit:
            r = self.a.post("/api/v1/provider/submit")
            assert r.status_code == 200, r.text
        return self

    def card(self, **over):
        payload = {"name": "Fix-It Agent", "version": "1.0.0", "description": "Resolves common IT issues",
                   "agent_kid": self.agent_key.kid, "build_digest": AGENT_BUILD,
                   "capabilities": {"categories": ["it.printing", "it.accounts"], "connectors": ["it-sim"],
                                    "max_level": "D2"}}
        payload.update(over)
        return self.org_key.sign(payload)

    def register_agent(self, **over):
        return self.a.post("/api/v1/provider/agents", json={"card": self.card(**over)})


def provider_signup(make_actor, name="Example Managed IT"):
    a = make_actor("provider", org_name=name)
    return a


def set_business_reg(app, actor, business_reg="REG-0000001"):
    org_id = actor.get("/api/v1/me").json()["org"]["id"]
    with app.state.engine.begin() as conn:
        conn.execute(text("UPDATE orgs SET business_reg = :n WHERE id = :i"), {"n": business_reg, "i": org_id})
    return org_id


def verified_provider(app, make_actor, admin, name="Example Managed IT"):
    a = provider_signup(make_actor, name)
    org_id = set_business_reg(app, a)
    kit = ProviderKit(a).onboard()
    assert admin.post(f"/api/v1/admin/providers/{org_id}/decision", json={"decision": "approve"}).status_code == 200
    return kit, org_id


def centre(client):
    return client.get("/.well-known/ai2ai/centre.json").json()


def test_full_onboarding_to_catalogue(app, client, make_actor, admin):
    a = provider_signup(make_actor)
    org_id = set_business_reg(app, a)
    kit = ProviderKit(a).onboard()
    assert a.get("/api/v1/provider/profile").json()["status"] == "submitted"
    pending = admin.get("/api/v1/admin/providers").json()
    assert [p["org_id"] for p in pending] == [org_id]
    assert admin.post(f"/api/v1/admin/providers/{org_id}/decision", json={"decision": "approve"}).status_code == 200
    prof = a.get("/api/v1/provider/profile").json()
    assert prof["status"] == "verified" and {c["kind"] for c in prof["credentials"]} == {"ISO27001", "PIInsurance"}
    r = kit.register_agent()
    assert r.status_code == 201 and r.json()["status"] == "listed"
    agent_id = r.json()["id"]
    assert a.post("/api/v1/provider/services", json={"agent_id": agent_id, "title": "Printer fixes", "category": "it.printing",
                                                     "level": "D2", "price_text": "$90 per job"}).status_code == 201
    customer = make_actor("customer")
    cat = customer.get("/api/v1/catalogue").json()
    assert len(cat) == 1 and cat[0]["provider"]["badges"] == ["ISO27001", "PIInsurance"]
    bundle = customer.get(f"/api/v1/agents/{agent_id}/listing").json()
    c = centre(client)
    ok, reasons, facts = verify_listing(bundle, c["public_key"], c["kid"])
    assert ok, reasons
    assert facts["agent_public_key"] == kit.agent_key.public_b64 and facts["max_level"] == "D2"
    assert customer.get("/api/v1/catalogue?category=it.network").json() == []


def test_submit_requirements(app, make_actor):
    a = provider_signup(make_actor)
    r = a.post("/api/v1/provider/submit")
    assert r.status_code == 422
    for need in ("business registration number", "security certification", "insurance", "signing key"):
        assert need in r.json()["detail"]
    set_business_reg(app, a)
    kit = ProviderKit(a).onboard(evidence=("ISO27001",), submit=False)
    r = a.post("/api/v1/provider/submit")
    assert r.status_code == 422 and "insurance" in r.json()["detail"]


def test_card_validation(app, make_actor, admin):
    kit, _ = verified_provider(app, make_actor, admin)
    stranger = Signer("provider-org")
    assert kit.a.post("/api/v1/provider/agents", json={"card": stranger.sign(kit.card()["payload"])}).status_code == 422
    tampered = kit.card()
    tampered["payload"]["capabilities"]["max_level"] = "D2"
    tampered["payload"]["name"] = "Changed after signing"
    assert kit.a.post("/api/v1/provider/agents", json={"card": tampered}).status_code == 422
    assert kit.register_agent(agent_kid=Signer("provider-agent").kid).status_code == 422
    assert kit.register_agent(capabilities={"categories": ["it.printing"], "connectors": ["it-sim"],
                                            "max_level": "D3"}).status_code == 422
    assert kit.register_agent(capabilities={"categories": ["Printing!"], "connectors": ["it-sim"],
                                            "max_level": "D1"}).status_code == 422
    assert kit.register_agent(build_digest="not-a-digest").status_code == 422


def test_unverified_agents_stay_hidden(app, make_actor, admin):
    a = provider_signup(make_actor)
    org_id = set_business_reg(app, a)
    kit = ProviderKit(a).onboard()
    r = kit.register_agent()
    assert r.json()["status"] == "draft"
    agent_id = r.json()["id"]
    a.post("/api/v1/provider/services", json={"agent_id": agent_id, "title": "Printer fixes",
                                              "category": "it.printing", "level": "D1"})
    customer = make_actor("customer")
    assert customer.get("/api/v1/catalogue").json() == []
    assert customer.get(f"/api/v1/agents/{agent_id}/listing").status_code == 404
    admin.post(f"/api/v1/admin/providers/{org_id}/decision", json={"decision": "approve"})
    assert len(customer.get("/api/v1/catalogue").json()) == 1


def test_service_validation(app, make_actor, admin):
    kit, _ = verified_provider(app, make_actor, admin)
    aid = kit.register_agent(capabilities={"categories": ["it.printing"], "connectors": ["it-sim"],
                                           "max_level": "D1"}).json()["id"]
    assert kit.a.post("/api/v1/provider/services", json={"agent_id": aid, "title": "Network", "category": "it.network",
                                                         "level": "D1"}).status_code == 422
    assert kit.a.post("/api/v1/provider/services", json={"agent_id": aid, "title": "Printers", "category": "it.printing",
                                                         "level": "D2"}).status_code == 422
    other, _ = verified_provider(app, make_actor, admin, name="Other IT")
    assert other.a.post("/api/v1/provider/services", json={"agent_id": aid, "title": "Steal", "category": "it.printing",
                                                           "level": "D1"}).status_code == 404


def test_reject_then_resubmit(app, make_actor, admin):
    a = provider_signup(make_actor)
    org_id = set_business_reg(app, a)
    ProviderKit(a).onboard()
    assert admin.post(f"/api/v1/admin/providers/{org_id}/decision",
                      json={"decision": "reject", "note": "insurance certificate unreadable"}).status_code == 200
    prof = a.get("/api/v1/provider/profile").json()
    assert prof["status"] == "rejected" and "unreadable" in prof["review_note"]
    assert a.post("/api/v1/provider/submit").status_code == 200


def test_revoking_a_credential_suspends_and_unlists(app, client, make_actor, admin):
    kit, org_id = verified_provider(app, make_actor, admin)
    aid = kit.register_agent().json()["id"]
    kit.a.post("/api/v1/provider/services", json={"agent_id": aid, "title": "Printers", "category": "it.printing",
                                                  "level": "D1"})
    customer = make_actor("customer")
    old_bundle = customer.get(f"/api/v1/agents/{aid}/listing").json()
    iso = next(c for c in kit.a.get("/api/v1/provider/profile").json()["credentials"] if c["kind"] == "ISO27001")
    assert admin.post(f"/api/v1/admin/credentials/{iso['id']}/revoke", json={"reason": "certificate withdrawn"}).status_code == 200
    assert kit.a.get("/api/v1/provider/profile").json()["status"] == "suspended"
    assert customer.get("/api/v1/catalogue").json() == []
    revoked = set(client.get("/.well-known/ai2ai/revocations.json").json()["items"])
    assert iso["id"] in revoked and org_id in revoked
    c = centre(client)
    ok, reasons, _ = verify_listing(old_bundle, c["public_key"], c["kid"], revoked=revoked)
    assert not ok and any("revoked" in r for r in reasons), "an edge holding the old bundle must still refuse it"


def test_withdrawn_agent_is_refused(app, client, make_actor, admin):
    kit, _ = verified_provider(app, make_actor, admin)
    aid = kit.register_agent().json()["id"]
    customer = make_actor("customer")
    bundle = customer.get(f"/api/v1/agents/{aid}/listing").json()
    assert kit.a.post(f"/api/v1/provider/agents/{aid}/withdraw").status_code == 200
    assert customer.get(f"/api/v1/agents/{aid}/listing").status_code == 404
    revoked = set(client.get("/.well-known/ai2ai/revocations.json").json()["items"])
    c = centre(client)
    assert not verify_listing(bundle, c["public_key"], c["kid"], revoked=revoked)[0]


def test_trust_bundle_tamper_detection(app, client, make_actor, admin):
    kit, _ = verified_provider(app, make_actor, admin)
    aid = kit.register_agent().json()["id"]
    customer = make_actor("customer")
    c = centre(client)
    good = customer.get(f"/api/v1/agents/{aid}/listing").json()
    import copy
    swapped = copy.deepcopy(good)
    swapped["countersig"]["payload"]["agent_public_key"] = Signer("provider-agent").public_b64
    assert not verify_listing(swapped, c["public_key"], c["kid"])[0]
    other_card = copy.deepcopy(good)
    other_card["card"] = kit.card(name="Different agent")
    assert not verify_listing(other_card, c["public_key"], c["kid"])[0]
    fake_centre = Signer("centre")
    forged = copy.deepcopy(good)
    forged["countersig"] = fake_centre.sign(good["countersig"]["payload"])
    assert not verify_listing(forged, c["public_key"], c["kid"])[0]
    no_creds = dict(good, credentials=[])
    ok, reasons, _ = verify_listing(no_creds, c["public_key"], c["kid"])
    assert not ok and any("missing valid" in r for r in reasons)


def test_role_boundaries(app, make_actor, admin):
    kit, org_id = verified_provider(app, make_actor, admin)
    customer = make_actor("customer")
    assert customer.get("/api/v1/provider/profile").status_code == 403
    assert customer.post("/api/v1/provider/keys", json={"purpose": "org", "public_key": Signer("provider-org").public_b64}).status_code == 403
    assert kit.a.post(f"/api/v1/admin/providers/{org_id}/decision", json={"decision": "approve"}).status_code == 403
    assert admin.post(f"/api/v1/admin/providers/{org_id}/decision", json={"decision": "approve"}, csrf=False).status_code == 403


def test_centre_never_holds_provider_private_keys(app, make_actor, admin):
    kit, _ = verified_provider(app, make_actor, admin)
    kit.register_agent()
    private_values = {b64u(kit.org_key.private_bytes()), b64u(kit.agent_key.private_bytes()),
                      kit.org_key.private_bytes().hex(), kit.agent_key.private_bytes().hex()}
    with app.state.engine.connect() as conn:
        for table in ("provider_keys", "agents", "credentials", "audit_events", "evidence_items"):
            dump = " ".join(str(row) for row in conn.execute(text(f"SELECT * FROM {table}")))
            for secret in private_values:
                assert secret not in dump, table


def test_duplicate_key_and_bad_key(make_actor):
    a = make_actor("provider")
    k = Signer("provider-org")
    assert a.post("/api/v1/provider/keys", json={"purpose": "org", "public_key": k.public_b64}).status_code == 201
    assert a.post("/api/v1/provider/keys", json={"purpose": "org", "public_key": k.public_b64}).status_code == 409
    assert a.post("/api/v1/provider/keys", json={"purpose": "root", "public_key": k.public_b64}).status_code == 422
    assert a.post("/api/v1/provider/keys", json={"purpose": "org", "public_key": "A" * 30}).status_code == 422
