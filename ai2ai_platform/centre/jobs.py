"""M5: edge registration, job index (metadata only), provider job polling, metering, matching.

Flow: the customer edge, after a human approved a Work Order, sends the centre a notice SIGNED BY ITS BROKER KEY.
The provider runtime polls with requests SIGNED BY ITS ORG KEY and then talks to the customer edge directly.
Task content (ticket, environment data, results) never passes through the centre."""
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from ..core.crypto import SignatureError, kid_for, unb64u, verify_with_public
from ..db import utcnow
from ..usecases import category_words, default_category
from .models import Agent, CentreNonce, CustomerEdge, JobIndex, Org, ProviderKey, ProviderProfile, Service
from .security import (Principal, audit, current_principal, endpoint_url_problem, get_db, require_roles,
                       require_roles_csrf)

router = APIRouter()
MAX_SKEW = 120


class EdgeIn(BaseModel):
    base_url: str = Field(min_length=8, max_length=300)
    broker_public_key: str = Field(min_length=40, max_length=60)


class SignedIn(BaseModel):
    envelope: dict


def _fresh(db, payload):
    n, ts = payload.get("nonce"), payload.get("ts")
    if not isinstance(n, str) or not isinstance(ts, (int, float)) or abs(time.time() - ts) > MAX_SKEW:
        raise HTTPException(403, "stale or malformed request")
    if db.get(CentreNonce, n):
        raise HTTPException(403, "replayed request")
    from datetime import timedelta
    db.query(CentreNonce).filter(CentreNonce.seen_at < utcnow() - timedelta(seconds=4 * MAX_SKEW)).delete(
        synchronize_session=False)
    db.add(CentreNonce(nonce=n))


# ----- customer registers its edge -----
@router.post("/api/v1/customer/edge")
def register_edge(body: EdgeIn, request: Request, p: Principal = Depends(require_roles_csrf("customer_admin")),
                  db=Depends(get_db)):
    problem = endpoint_url_problem(body.base_url, production=request.app.state.settings.https)
    if problem:
        raise HTTPException(422, f"base_url {problem}")
    try:
        raw = unb64u(body.broker_public_key)
        assert len(raw) == 32
    except Exception:
        raise HTTPException(422, "broker_public_key must be a base64url Ed25519 public key")
    edge = db.get(CustomerEdge, p.org.id) or CustomerEdge(org_id=p.org.id)
    edge.base_url, edge.broker_public_key = body.base_url.rstrip("/"), body.broker_public_key
    edge.broker_kid = kid_for("customer-broker", raw)
    db.merge(edge)
    db.commit()
    audit(db, "customer.edge_registered", p.user, p.org.id, base_url=edge.base_url, kid=edge.broker_kid)
    return {"broker_kid": edge.broker_kid}


def _edge_verified(db, envelope, expected_type):
    org_id = (envelope.get("payload") or {}).get("customer_org")
    edge = db.get(CustomerEdge, str(org_id))
    if edge is None:
        raise HTTPException(403, "unknown customer edge")
    try:
        payload = verify_with_public(envelope, edge.broker_public_key, expected_kid=edge.broker_kid)
    except SignatureError as exc:
        raise HTTPException(403, f"notice not signed by the customer's registered edge ({exc})")
    if payload.get("type") != expected_type:
        raise HTTPException(422, "wrong notice type")
    _fresh(db, payload)
    return edge, payload


@router.get("/api/v1/customer/edge")
def my_edge(p: Principal = Depends(require_roles("customer_admin", "customer_approver", "customer_member")),
            db=Depends(get_db)):
    edge = db.get(CustomerEdge, p.org.id)
    return {"base_url": edge.base_url if edge else None}


# ----- edge -> centre notices -----
@router.post("/api/v1/edge/jobs/notice", status_code=201)
def job_notice(body: SignedIn, db=Depends(get_db)):
    edge, n = _edge_verified(db, body.envelope, "JobNotice")
    agent = db.get(Agent, str(n.get("agent_id")))
    if agent is None or agent.status != "listed" or agent.org_id != n.get("provider_org"):
        raise HTTPException(422, "agent not listed for that provider")
    if db.get(JobIndex, str(n.get("wo_id"))):
        raise HTTPException(409, "job already indexed")
    db.add(JobIndex(wo_id=n["wo_id"], customer_org_id=edge.org_id, provider_org_id=agent.org_id, agent_id=agent.id,
                    edge_url=edge.base_url, level=str(n.get("level", ""))))
    db.commit()
    return {"ok": True}


@router.post("/api/v1/edge/jobs/update")
def job_update(body: SignedIn, db=Depends(get_db)):
    edge, n = _edge_verified(db, body.envelope, "JobUpdate")
    j = db.get(JobIndex, str(n.get("wo_id")))
    if j is None or j.customer_org_id != edge.org_id:
        raise HTTPException(404, "job not found")
    status = n.get("status")
    if status not in ("completed", "canceled"):
        raise HTTPException(422, "status must be completed or canceled")
    j.status, j.outcome = status, str(n.get("outcome", ""))[:40]
    j.changes_count, j.escalated = int(n.get("changes_count", 0)), bool(n.get("escalated", False))
    j.receipt_digest = str(n.get("receipt_digest", ""))[:64]
    j.completed_at = utcnow()
    db.commit()
    return {"ok": True}


# ----- provider runtime polls (signed by the provider org key, no session) -----
def _provider_verified(db, envelope, expected_type):
    kid = (envelope or {}).get("kid", "")
    key = db.get(ProviderKey, kid)
    if key is None or key.purpose != "org" or key.revoked:
        raise HTTPException(403, "unknown provider key")
    try:
        payload = verify_with_public(envelope, key.public_key, expected_kid=kid)
    except SignatureError as exc:
        raise HTTPException(403, f"bad signature ({exc})")
    if payload.get("type") != expected_type:
        raise HTTPException(422, "wrong request type")
    prof = db.get(ProviderProfile, key.org_id)
    org = db.get(Org, key.org_id)
    if prof is None or prof.status != "verified" or org.status != "active":
        raise HTTPException(403, "provider not verified")
    _fresh(db, payload)
    return key.org_id, payload


@router.post("/api/v1/provider/jobs/poll")
def provider_poll(body: SignedIn, db=Depends(get_db)):
    org_id, _ = _provider_verified(db, body.envelope, "Poll")
    rows = db.execute(select(JobIndex).where(JobIndex.provider_org_id == org_id, JobIndex.status == "notified")
                      .order_by(JobIndex.created_at)).scalars()
    out = [{"wo_id": j.wo_id, "agent_id": j.agent_id, "edge_url": j.edge_url, "level": j.level} for j in rows]
    db.commit()
    return {"jobs": out}


@router.post("/api/v1/provider/jobs/ack")
def provider_ack(body: SignedIn, db=Depends(get_db)):
    org_id, p = _provider_verified(db, body.envelope, "Ack")
    j = db.get(JobIndex, str(p.get("wo_id")))
    if j is None or j.provider_org_id != org_id:
        raise HTTPException(404, "job not found")
    if j.status == "notified":
        j.status = "picked_up"
    db.commit()
    return {"ok": True}


@router.post("/api/v1/provider/jobs/lookup")
def provider_lookup(body: SignedIn, db=Depends(get_db)):
    """Trusted routing facts for ONE job routed to the calling provider: the customer edge's registered URL and
    PUBLIC broker key. Used by provider A2A endpoints so they never trust a caller-supplied address."""
    org_id, p = _provider_verified(db, body.envelope, "Lookup")
    j = db.get(JobIndex, str(p.get("wo_id")))
    if j is None or j.provider_org_id != org_id:
        raise HTTPException(404, "job not found")
    edge = db.get(CustomerEdge, j.customer_org_id)
    db.commit()
    return {"wo_id": j.wo_id, "agent_id": j.agent_id, "edge_url": j.edge_url, "status": j.status,
            "broker_kid": edge.broker_kid, "broker_public_key": edge.broker_public_key}


# ----- metering -----
def _usage(db, where):
    rows = db.execute(select(JobIndex.agent_id, JobIndex.status, func.count(), func.sum(JobIndex.changes_count))
                      .where(where).group_by(JobIndex.agent_id, JobIndex.status)).all()
    out = {}
    for agent_id, status, n, changes in rows:
        a = out.setdefault(agent_id, {"agent_id": agent_id, "jobs": 0, "completed": 0, "canceled": 0, "changes": 0})
        a["jobs"] += n
        a["changes"] += int(changes or 0)
        if status in ("completed", "canceled"):
            a[status] += n
    return sorted(out.values(), key=lambda x: x["agent_id"])


@router.get("/api/v1/provider/usage")
def provider_usage(p: Principal = Depends(require_roles("provider_admin")), db=Depends(get_db)):
    return _usage(db, JobIndex.provider_org_id == p.org.id)


@router.get("/api/v1/customer/jobs")
def customer_jobs(p: Principal = Depends(require_roles("customer_admin", "customer_approver", "customer_member")),
                  db=Depends(get_db)):
    return [{"wo_id": j.wo_id, "agent_id": j.agent_id, "status": j.status, "outcome": j.outcome, "level": j.level,
             "receipt_digest": j.receipt_digest} for j in
            db.execute(select(JobIndex).where(JobIndex.customer_org_id == p.org.id)
                       .order_by(JobIndex.created_at.desc())).scalars()]


@router.get("/api/v1/admin/usage")
def admin_usage(p: Principal = Depends(require_roles("platform_admin")), db=Depends(get_db)):
    return _usage(db, JobIndex.wo_id.is_not(None))

# ----- matching: plain-words issue -> category -> verified services -----

CATEGORY_WORDS = category_words()  # merged from every registered use case


def classify(text: str) -> list:
    t = f" {text.lower()} "
    scores = {c: sum(t.count(w) for w in words) for c, words in CATEGORY_WORDS.items()}
    ranked = [c for c, s in sorted(scores.items(), key=lambda x: (-x[1], x[0])) if s > 0]
    return ranked or [default_category()]


@router.get("/api/v1/match")
def match(q: str, level: str = "D2", db=Depends(get_db)):
    """Public: only marketplace data (verified services, badges, completed-job counts)."""
    cats = classify(q)
    from .providers import _valid_credentials
    rank_of = {c: i for i, c in enumerate(cats)}
    q_ = (select(Service, Agent, Org, ProviderProfile).join(Agent, Agent.id == Service.agent_id)
          .join(Org, Org.id == Service.org_id).join(ProviderProfile, ProviderProfile.org_id == Org.id)
          .where(Service.status == "active", Agent.status == "listed", ProviderProfile.status == "verified",
                 Org.status == "active", Service.category.in_(cats)))
    results = []
    for s, a, org, prof in db.execute(q_).all():
        completed = db.execute(select(func.count()).select_from(JobIndex).where(
            JobIndex.agent_id == a.id, JobIndex.status == "completed")).scalar()
        results.append({"service_id": s.id, "title": s.title, "category": s.category, "level": s.level,
                        "price_text": s.price_text, "agent_id": a.id, "agent_name": a.name, "provider": org.name,
                        "badges": sorted({c.kind for c in _valid_credentials(db, org.id)}),
                        "completed_jobs": completed, "_rank": rank_of[s.category]})
    level_ok = [r for r in results if (r["level"] == "D2") or level == "D1"]
    level_ok.sort(key=lambda r: (r["_rank"], -r["completed_jobs"], r["provider"]))
    for r in level_ok:
        r.pop("_rank")
    return {"categories": cats, "matches": level_ok}
