"""M2: provider onboarding, admin verification, credentials, agent listings, service catalogue, revocation.

The centre stores providers' PUBLIC keys and their self-signed agent cards. It never receives private keys, prompts
or agent code. A listing becomes visible only when the provider is verified AND the centre has countersigned it."""
import re
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from ..core.crypto import SignatureError, digest, kid_for, new_nonce, unb64u, verify_with_public
from ..core.trust import LEVEL_RANK, required_credentials_met
from ..db import utcnow
from .models import (EVIDENCE_KINDS, Agent, Credential, EvidenceItem, Notification, Org, ProviderKey, ProviderProfile,
                     Revocation, Service)
from .security import (Principal, audit, current_principal, endpoint_url_problem, get_db, require_roles,
                       require_roles_csrf)

router = APIRouter()
CATEGORY_RE = re.compile(r"^[a-z][a-z0-9]*(\.[a-z0-9-]+)+$")
LISTING_DAYS = 30
KEY_LABEL = {"org": "provider-org", "agent": "provider-agent", "technician": "provider-technician"}

provider_admin = require_roles("provider_admin")
provider_admin_csrf = require_roles_csrf("provider_admin")
platform_admin = require_roles("platform_admin")
platform_admin_csrf = require_roles_csrf("platform_admin")


def _aware(dt):
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _profile(db, org_id) -> ProviderProfile:
    prof = db.get(ProviderProfile, org_id)
    if prof is None:
        prof = ProviderProfile(org_id=org_id)
        db.add(prof)
        db.flush()
    return prof


# ----- request bodies -----
class ProfileIn(BaseModel):
    description: str = Field(default="", max_length=2000)
    website: str = Field(default="", max_length=300)
    contact_email: str = Field(default="", max_length=254)


class EvidenceIn(BaseModel):
    kind: str
    reference: str = Field(min_length=2, max_length=200)
    issuer: str = Field(min_length=2, max_length=200)
    expires_on: str  # YYYY-MM-DD


class KeyIn(BaseModel):
    purpose: str
    public_key: str = Field(min_length=20, max_length=100)


class AgentIn(BaseModel):
    card: dict  # envelope signed by the provider's org key


class ServiceIn(BaseModel):
    agent_id: str
    title: str = Field(min_length=3, max_length=200)
    category: str
    level: str
    description: str = Field(default="", max_length=2000)
    price_text: str = Field(default="", max_length=200)


class DecisionIn(BaseModel):
    decision: str  # approve | reject
    note: str = Field(default="", max_length=1000)


class ReasonIn(BaseModel):
    reason: str = Field(min_length=3, max_length=500)


# ----- provider side -----
@router.get("/api/v1/provider/profile")
def get_profile(p: Principal = Depends(provider_admin), db=Depends(get_db)):
    prof = _profile(db, p.org.id)
    db.commit()
    ev = db.execute(select(EvidenceItem).where(EvidenceItem.org_id == p.org.id)).scalars()
    keys = db.execute(select(ProviderKey).where(ProviderKey.org_id == p.org.id)).scalars()
    creds = db.execute(select(Credential).where(Credential.org_id == p.org.id)).scalars()
    return {"status": prof.status, "description": prof.description, "website": prof.website,
            "contact_email": prof.contact_email, "review_note": prof.review_note, "business_reg": p.org.business_reg,
            "evidence": [{"id": e.id, "kind": e.kind, "reference": e.reference, "issuer": e.issuer,
                          "expires_on": e.expires_on.date().isoformat()} for e in ev],
            "keys": [{"kid": k.kid, "purpose": k.purpose, "revoked": k.revoked} for k in keys],
            "credentials": [{"id": c.id, "kind": c.kind, "revoked": c.revoked} for c in creds]}


@router.put("/api/v1/provider/profile")
def put_profile(body: ProfileIn, p: Principal = Depends(provider_admin_csrf), db=Depends(get_db)):
    prof = _profile(db, p.org.id)
    if prof.status in ("submitted", "verified"):
        raise HTTPException(409, "profile is locked while under review or verified; contact the platform")
    prof.description, prof.website, prof.contact_email = body.description, body.website, body.contact_email
    db.commit()
    return {"ok": True}


@router.post("/api/v1/provider/evidence", status_code=201)
def add_evidence(body: EvidenceIn, p: Principal = Depends(provider_admin_csrf), db=Depends(get_db)):
    if body.kind not in EVIDENCE_KINDS:
        raise HTTPException(422, f"kind must be one of {EVIDENCE_KINDS}")
    try:
        exp = datetime.strptime(body.expires_on, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        raise HTTPException(422, "expires_on must be YYYY-MM-DD")
    if exp <= utcnow():
        raise HTTPException(422, "evidence has already expired")
    e = EvidenceItem(org_id=p.org.id, kind=body.kind, reference=body.reference, issuer=body.issuer, expires_on=exp)
    db.add(e)
    db.commit()
    audit(db, "provider.evidence_added", p.user, p.org.id, kind=e.kind)
    return {"id": e.id}


@router.post("/api/v1/provider/keys", status_code=201)
def register_key(body: KeyIn, p: Principal = Depends(provider_admin_csrf), db=Depends(get_db)):
    label = KEY_LABEL.get(body.purpose)
    if not label:
        raise HTTPException(422, "purpose must be org, agent or technician")
    try:
        raw = unb64u(body.public_key)
        if len(raw) != 32:
            raise ValueError
    except ValueError:
        raise HTTPException(422, "public_key must be a base64url Ed25519 public key (32 bytes)")
    kid = kid_for(label, raw)
    if db.get(ProviderKey, kid):
        raise HTTPException(409, "key already registered")
    db.add(ProviderKey(kid=kid, org_id=p.org.id, purpose=body.purpose, public_key=body.public_key))
    db.commit()
    audit(db, "provider.key_registered", p.user, p.org.id, kid=kid, purpose=body.purpose)
    return {"kid": kid}


@router.post("/api/v1/provider/submit")
def submit(p: Principal = Depends(provider_admin_csrf), db=Depends(get_db)):
    prof = _profile(db, p.org.id)
    if prof.status not in ("draft", "rejected"):
        raise HTTPException(409, f"cannot submit from status {prof.status}")
    problems = []
    if not p.org.business_reg:
        problems.append("business registration number")
    kinds = {e.kind for e in db.execute(select(EvidenceItem).where(EvidenceItem.org_id == p.org.id)).scalars()}
    problems += required_credentials_met(kinds)
    if not db.execute(select(ProviderKey).where(ProviderKey.org_id == p.org.id, ProviderKey.purpose == "org",
                                                ProviderKey.revoked.is_(False))).first():
        problems.append("an organisation signing key")
    if problems:
        raise HTTPException(422, "before submitting, add: " + "; ".join(problems))
    prof.status, prof.submitted_at = "submitted", utcnow()
    platform = db.execute(select(Org).where(Org.kind == "platform")).scalar_one_or_none()
    if platform:
        notify(db, platform.id, "provider.submitted", f"{p.org.name} submitted evidence for verification",
               "platform_admin")
    db.commit()
    audit(db, "provider.submitted", p.user, p.org.id)
    return {"status": prof.status}


def _validate_card(db, org_id: str, envelope: dict, production: bool = False) -> dict:
    kid = (envelope or {}).get("kid", "")
    key = db.get(ProviderKey, kid)
    if key is None or key.org_id != org_id or key.purpose != "org" or key.revoked:
        raise HTTPException(422, "card must be signed by your registered, active organisation key")
    try:
        card = verify_with_public(envelope, key.public_key, expected_kid=kid)
    except SignatureError as exc:
        raise HTTPException(422, f"card signature invalid: {exc}")
    for f in ("name", "version", "description", "agent_kid", "build_digest", "capabilities"):
        if f not in card:
            raise HTTPException(422, f"card missing {f}")
    akey = db.get(ProviderKey, card["agent_kid"])
    if akey is None or akey.org_id != org_id or akey.purpose != "agent" or akey.revoked:
        raise HTTPException(422, "agent_kid must be one of your registered, active agent keys")
    cap = card["capabilities"]
    if cap.get("max_level") not in LEVEL_RANK or LEVEL_RANK[cap["max_level"]] > 2:
        raise HTTPException(422, "max_level must be D1 or D2 in v1")
    cats = cap.get("categories") or []
    if not cats or not all(isinstance(c, str) and CATEGORY_RE.match(c) for c in cats):
        raise HTTPException(422, "categories must look like 'it.printing' (domain.area)")
    if not isinstance(cap.get("connectors"), list) or not cap["connectors"]:
        raise HTTPException(422, "connectors must list the environment connectors the agent needs, e.g. ['it-sim']")
    if not re.fullmatch(r"[0-9a-f]{64}", str(card["build_digest"])):
        raise HTTPException(422, "build_digest must be a SHA-256 hex digest of the agent build")
    if "a2a_url" in cap:  # the centre vouches for this URL in its own signed A2A card
        problem = endpoint_url_problem(cap["a2a_url"], production=production, path_allowed=True)
        if problem:
            raise HTTPException(422, f"a2a_url {problem}")
    return card


@router.post("/api/v1/provider/agents", status_code=201)
def register_agent(body: AgentIn, request: Request, p: Principal = Depends(provider_admin_csrf), db=Depends(get_db)):
    card = _validate_card(db, p.org.id, body.card, production=request.app.state.settings.https)
    a = Agent(org_id=p.org.id, name=card["name"], version=card["version"], card=body.card, status="draft")
    db.add(a)
    db.flush()
    prof = _profile(db, p.org.id)
    if prof.status == "verified":
        _countersign(db, request.app.state.centre_signer, a, p.org)
    db.commit()
    audit(db, "provider.agent_registered", p.user, p.org.id, agent=a.id, version=a.version,
          build_digest=card["build_digest"])
    return {"id": a.id, "status": a.status}


@router.get("/api/v1/provider/agents")
def my_agents(p: Principal = Depends(provider_admin), db=Depends(get_db)):
    return [{"id": a.id, "name": a.name, "version": a.version, "status": a.status}
            for a in db.execute(select(Agent).where(Agent.org_id == p.org.id)).scalars()]


@router.post("/api/v1/provider/agents/{agent_id}/withdraw")
def withdraw_agent(agent_id: str, p: Principal = Depends(provider_admin_csrf), db=Depends(get_db)):
    a = db.get(Agent, agent_id)
    if a is None or a.org_id != p.org.id:
        raise HTTPException(404, "agent not found")
    a.status = "withdrawn"
    _revoke_item(db, a.id, "agent", "withdrawn by provider")
    db.commit()
    audit(db, "provider.agent_withdrawn", p.user, p.org.id, agent=a.id)
    return {"ok": True}


@router.get("/api/v1/provider/services")
def my_services(p: Principal = Depends(provider_admin), db=Depends(get_db)):
    return [{"id": s.id, "agent_id": s.agent_id, "title": s.title, "category": s.category, "level": s.level,
             "price_text": s.price_text, "status": s.status}
            for s in db.execute(select(Service).where(Service.org_id == p.org.id)).scalars()]


@router.post("/api/v1/provider/services", status_code=201)
def add_service(body: ServiceIn, p: Principal = Depends(provider_admin_csrf), db=Depends(get_db)):
    a = db.get(Agent, body.agent_id)
    if a is None or a.org_id != p.org.id:
        raise HTTPException(404, "agent not found")
    cap = a.card["payload"]["capabilities"]
    if body.category not in cap["categories"]:
        raise HTTPException(422, "the agent's card does not declare this category")
    if body.level not in LEVEL_RANK or LEVEL_RANK[body.level] > LEVEL_RANK[cap["max_level"]]:
        raise HTTPException(422, f"level must be at most the agent's max_level {cap['max_level']}")
    s = Service(org_id=p.org.id, agent_id=a.id, title=body.title, category=body.category, level=body.level,
                description=body.description, price_text=body.price_text)
    db.add(s)
    db.commit()
    audit(db, "provider.service_added", p.user, p.org.id, service=s.id)
    return {"id": s.id}


# ----- centre signing helpers -----
def _valid_credentials(db, org_id):
    now = utcnow()
    return [c for c in db.execute(select(Credential).where(Credential.org_id == org_id,
                                                            Credential.revoked.is_(False))).scalars()
            if _aware(c.expires_at) > now]


def _countersign(db, signer, agent: Agent, org: Org):
    card = agent.card["payload"]
    okey = db.get(ProviderKey, agent.card["kid"])
    akey = db.get(ProviderKey, card["agent_kid"])
    now = time.time()
    agent.countersig = signer.sign({
        "type": "ListingCountersignature", "agent_id": agent.id, "org_id": org.id, "org_name": org.name,
        "org_kid": okey.kid, "org_public_key": okey.public_key, "agent_kid": akey.kid,
        "agent_public_key": akey.public_key, "card_digest": digest(agent.card),
        "technician_keys": [{"kid": k.kid, "public_key": k.public_key} for k in db.execute(
            select(ProviderKey).where(ProviderKey.org_id == org.id, ProviderKey.purpose == "technician",
                                      ProviderKey.revoked.is_(False))).scalars()],
        "credential_ids": [c.id for c in _valid_credentials(db, org.id)], "issued": now,
        "expires": now + LISTING_DAYS * 86400})
    agent.status = "listed"


def notify(db, org_id, kind, text, role=""):
    db.add(Notification(org_id=org_id, kind=kind, text=text[:500], role=role))


def _revoke_item(db, item, kind, reason):
    if not db.get(Revocation, item):
        db.add(Revocation(item=item, kind=kind, reason=reason))


def _reevaluate(db, signer, org: Org, actor):
    """After a revocation: suspend the provider and unlist its agents if requirements are no longer met."""
    prof = _profile(db, org.id)
    kinds = {c.kind for c in _valid_credentials(db, org.id)}
    if prof.status == "verified" and required_credentials_met(kinds):
        prof.status = "suspended"
        for a in db.execute(select(Agent).where(Agent.org_id == org.id, Agent.status == "listed")).scalars():
            a.status = "draft"
        _revoke_item(db, org.id, "org", "provider suspended: credentials no longer valid")
        db.commit()
        audit(db, "provider.suspended", actor, org.id, reason="credentials no longer meet requirements")
    else:
        for a in db.execute(select(Agent).where(Agent.org_id == org.id, Agent.status == "listed")).scalars():
            _countersign(db, signer, a, org)  # refresh credential ids in the countersignature
        db.commit()


# ----- platform admin -----
@router.get("/api/v1/admin/providers")
def admin_providers(status: str = "submitted", p: Principal = Depends(platform_admin), db=Depends(get_db)):
    rows = db.execute(select(ProviderProfile, Org).join(Org, Org.id == ProviderProfile.org_id)
                      .where(ProviderProfile.status == status)).all()
    out = []
    for prof, org in rows:
        ev = db.execute(select(EvidenceItem).where(EvidenceItem.org_id == org.id)).scalars()
        out.append({"org_id": org.id, "name": org.name, "business_reg": org.business_reg, "status": prof.status,
                    "description": prof.description, "website": prof.website,
                    "evidence": [{"id": e.id, "kind": e.kind, "reference": e.reference, "issuer": e.issuer,
                                  "expires_on": e.expires_on.date().isoformat()} for e in ev]})
    return out


@router.post("/api/v1/admin/providers/{org_id}/decision")
def admin_decide(org_id: str, body: DecisionIn, request: Request, p: Principal = Depends(platform_admin_csrf),
                 db=Depends(get_db)):
    org = db.get(Org, org_id)
    prof = db.get(ProviderProfile, org_id)
    if org is None or prof is None or org.kind != "provider":
        raise HTTPException(404, "provider not found")
    if prof.status != "submitted":
        raise HTTPException(409, f"provider is {prof.status}, not awaiting review")
    if body.decision == "reject":
        prof.status, prof.review_note = "rejected", body.note
        notify(db, org.id, "provider.rejected", f"Verification was not approved: {body.note or 'see the review note'}")
        db.commit()
        audit(db, "provider.rejected", p.user, org.id, note=body.note)
        return {"status": prof.status}
    if body.decision != "approve":
        raise HTTPException(422, "decision must be approve or reject")
    signer = request.app.state.centre_signer
    for e in db.execute(select(EvidenceItem).where(EvidenceItem.org_id == org.id)).scalars():
        exp = _aware(e.expires_on)
        if exp <= utcnow():
            continue
        cid = f"{e.kind}-{new_nonce()}"
        env = signer.sign({"type": "VerifiableCredential", "id": cid, "credential_type": e.kind,
                           "subject_org": org.id, "subject_name": org.name, "subject_business_reg": org.business_reg,
                           "issuer_checked": e.issuer,
                           "issued": time.time(), "expires": exp.timestamp(), "verified_by": "platform-admin"})
        db.add(Credential(id=cid, org_id=org.id, kind=e.kind, envelope=env, expires_at=exp))
    db.flush()
    prof.status, prof.verified_at, prof.verified_by, prof.review_note = "verified", utcnow(), p.user.id, body.note
    notify(db, org.id, "provider.verified", "Your organisation is verified; your agents are now listed")
    for a in db.execute(select(Agent).where(Agent.org_id == org.id, Agent.status == "draft")).scalars():
        _countersign(db, signer, a, org)
    db.commit()
    audit(db, "provider.verified", p.user, org.id)
    return {"status": prof.status}


@router.post("/api/v1/admin/credentials/{cred_id}/revoke")
def admin_revoke_credential(cred_id: str, body: ReasonIn, request: Request,
                            p: Principal = Depends(platform_admin_csrf), db=Depends(get_db)):
    c = db.get(Credential, cred_id)
    if c is None:
        raise HTTPException(404, "credential not found")
    c.revoked, c.revoked_reason = True, body.reason
    _revoke_item(db, c.id, "credential", body.reason)
    notify(db, c.org_id, "credential.revoked", f"Your {c.kind} credential was revoked: {body.reason}")
    db.commit()
    audit(db, "credential.revoked", p.user, c.org_id, credential=c.id, reason=body.reason)
    _reevaluate(db, request.app.state.centre_signer, db.get(Org, c.org_id), p.user)
    return {"ok": True}


# ----- marketplace (any signed-in user) and public trust material -----
@router.get("/api/v1/catalogue")
def catalogue(category: str | None = None, p: Principal = Depends(current_principal), db=Depends(get_db)):
    q = (select(Service, Agent, Org, ProviderProfile).join(Agent, Agent.id == Service.agent_id)
         .join(Org, Org.id == Service.org_id).join(ProviderProfile, ProviderProfile.org_id == Org.id)
         .where(Service.status == "active", Agent.status == "listed", ProviderProfile.status == "verified",
                Org.status == "active"))
    if category:
        q = q.where(Service.category == category)
    out = []
    for s, a, org, prof in db.execute(q).all():
        badges = sorted({c.kind for c in _valid_credentials(db, org.id)})
        out.append({"service_id": s.id, "title": s.title, "category": s.category, "level": s.level,
                    "description": s.description, "price_text": s.price_text,
                    "provider": {"org_id": org.id, "name": org.name, "badges": badges},
                    "agent": {"id": a.id, "name": a.name, "version": a.version,
                              "max_level": a.card["payload"]["capabilities"]["max_level"]}})
    return out


@router.get("/api/v1/agents/{agent_id}/listing")
def listing_bundle(agent_id: str, db=Depends(get_db)):
    """Public, signed marketplace data (card, countersignature, credentials). Edges fetch it and verify it."""
    a = db.get(Agent, agent_id)
    if a is None or a.status != "listed" or a.countersig is None:
        raise HTTPException(404, "agent not listed")
    creds = [c.envelope for c in _valid_credentials(db, a.org_id)]
    return {"card": a.card, "countersig": a.countersig, "credentials": creds}


@router.get("/api/v1/notifications")
def my_notifications(p: Principal = Depends(current_principal), db=Depends(get_db)):
    rows = db.execute(select(Notification).where(Notification.org_id == p.org.id)
                      .order_by(Notification.created_at.desc()).limit(50)).scalars()
    return [{"id": n.id, "kind": n.kind, "text": n.text, "read": n.read, "email_queued": n.email_queued}
            for n in rows if not n.role or n.role == p.role]


@router.get("/a2a/agents/{agent_id}/agent-card.json")
def a2a_card(agent_id: str, request: Request, db=Depends(get_db)):
    """Marketplace-attested A2A v1.0.1 Agent Card (signed by the centre) for agents whose provider runs an A2A
    endpoint. The provider's own endpoint serves the same card signed with the provider's org key."""
    from ..core.a2a import card_from_listing, sign_card
    a = db.get(Agent, agent_id)
    if a is None or a.status != "listed" or a.countersig is None:
        raise HTTPException(404, "agent not listed")
    a2a_url = a.card["payload"]["capabilities"].get("a2a_url")
    if not a2a_url:
        raise HTTPException(404, "this agent does not offer an A2A endpoint")
    bundle = {"card": a.card, "countersig": a.countersig, "credentials": [c.envelope for c in _valid_credentials(db, a.org_id)]}
    card = card_from_listing(bundle, a2a_url, {"listing": bundle})
    return sign_card(card, request.app.state.centre_signer)


@router.get("/.well-known/ai2ai/centre.json")
def centre_key(request: Request):
    s = request.app.state.centre_signer
    return {"kid": s.kid, "public_key": s.public_b64, "alg": "EdDSA"}


@router.get("/.well-known/ai2ai/revocations.json")
def revocations(db=Depends(get_db)):
    return {"items": sorted(r.item for r in db.execute(select(Revocation)).scalars())}
