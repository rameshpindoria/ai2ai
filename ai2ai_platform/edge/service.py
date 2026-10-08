"""Customer edge logic: passkeys, verified job drafting, tokens, broker, step-up approvals, snapshot/rollback, kill
switch, per-job audit chain, receipts, amendments, local transparency log.

Every control point is held here, on the customer's side. Agents reach the environment only through `call` and
`change`, and only with a short-lived token issued by this edge's IdP after a human approved the Work Order."""
import hashlib
import json
import os
import secrets
import threading
import time
from datetime import timedelta

from sqlalchemy import select
from webauthn import (generate_authentication_options, generate_registration_options, options_to_json,
                      verify_authentication_response, verify_registration_response)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor,
                                      ResidentKeyRequirement, UserVerificationRequirement)

from ..core.crypto import SignatureError, canonical, digest, new_nonce, sha256, verify_with_public
from ..core.trust import LEVEL_RANK, required_credentials_met, verify_listing
from ..core.untrusted import wrap_untrusted
from ..connector import Connector, Environment, OpError
from ..db import utcnow
from ..usecases import load_connector
from .models import (AssistantToken, Challenge, Change, EdgeNotification, EdgeSession, EdgeUser, Enrolment,
                     EstateState, Job, JobAudit, PasskeyCred, SeenNonce, StepUp, Transparency)

LEVEL_CLASSES = {"D1": ["read"], "D2": ["read", "reversible"]}
TOKEN_TTL = 300
APPROVAL_TTL = 300
CHALLENGE_TTL = 120
MAX_SKEW = 60
GENESIS = "0" * 64
TERMINAL = {"completed", "canceled", "rejected"}


class EdgeError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def command_hash(wo_id: str, op: str, args: dict) -> str:
    return digest({"wo_id": wo_id, "op": op, "args": args})


def _aware(dt):
    from datetime import timezone
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class EdgeService:
    def __init__(self, settings, session_factory, signers, centre_key: dict, revocations_fetcher, centre_notifier=None,
                 listing_fetcher=None, connector: Connector = None):
        self.s = settings
        self.connector = connector or load_connector(getattr(settings, "usecase", None))
        self.sf = session_factory
        self.idp, self.approver, self.broker = signers["idp"], signers["approver"], signers["broker"]
        self.centre_key = centre_key
        self.fetch_revocations = revocations_fetcher
        self.estate_lock = threading.Lock()
        self.fail_next_postcheck = False  # test hook: simulate a change that did not take effect
        self.notify_centre = centre_notifier or (lambda path, envelope: None)
        self.fetch_listing = listing_fetcher

    def _notice(self, job, kind, path, **extra):
        """Metadata-only notice to the centre, signed with this edge's broker key. Never task content."""
        env = self.broker.sign(dict({"type": kind, "customer_org": self.s.org_id, "wo_id": job.wo_id,
                                     "nonce": new_nonce(), "ts": time.time()}, **extra))
        try:
            self.notify_centre(path, env)
        except Exception as exc:  # the job still works locally; the centre index catches up later
            self._last_notice_error = str(exc)

    # ================= audit + transparency =================
    def audit(self, db, job_id, actor, event, detail, outcome="info"):
        last = db.execute(select(JobAudit).where(JobAudit.job_id == job_id).order_by(JobAudit.seq.desc())
                          .limit(1)).scalar_one_or_none()
        prev, seq = (last.hash, last.seq + 1) if last else (GENESIS, 0)
        body = {"job": job_id, "seq": seq, "ts": round(time.time(), 3), "actor": actor, "event": event,
                "detail": detail, "outcome": outcome, "prev": prev}
        h = sha256(prev.encode() + canonical(body))
        db.add(JobAudit(job_id=job_id, seq=seq, ts=body["ts"], actor=actor, event=event, detail=detail,
                        outcome=outcome, prev=prev, hash=h))
        db.flush()
        return h

    def audit_entries(self, db, job_id):
        return list(db.execute(select(JobAudit).where(JobAudit.job_id == job_id).order_by(JobAudit.seq)).scalars())

    def verify_audit(self, db, job_id):
        prev = GENESIS
        for e in self.audit_entries(db, job_id):
            body = {"job": e.job_id, "seq": e.seq, "ts": e.ts, "actor": e.actor, "event": e.event, "detail": e.detail,
                    "outcome": e.outcome, "prev": prev}
            if e.prev != prev or sha256(prev.encode() + canonical(body)) != e.hash:
                return False, e.seq
            prev = e.hash
        return True, None

    def audit_root(self, db, job_id):
        entries = self.audit_entries(db, job_id)
        return entries[-1].hash if entries else GENESIS

    def anchor(self, db, kind, record):
        last = db.execute(select(Transparency).order_by(Transparency.seq.desc()).limit(1)).scalar_one_or_none()
        prev = last.hash if last else GENESIS
        body = {"ts": round(time.time(), 3), "kind": kind, "record_digest": digest(record), "prev": prev}
        h = sha256(prev.encode() + canonical(body))
        db.add(Transparency(ts=body["ts"], kind=kind, record_digest=body["record_digest"], prev=prev, hash=h))
        db.flush()
        return h

    # ================= notifications + assistant tokens =================
    def notify(self, db, job_id, kind, text):
        db.add(EdgeNotification(ts=time.time(), kind=kind, job_id=job_id, text=text[:1000]))
        db.flush()

    def notifications(self, db, unread_only=False):
        q = select(EdgeNotification).order_by(EdgeNotification.id.desc()).limit(50)
        rows = list(db.execute(q).scalars())
        return [{"id": n.id, "kind": n.kind, "job_id": n.job_id, "text": n.text, "read": n.read,
                 "email_queued": n.email_queued} for n in rows if not (unread_only and n.read)]

    def new_assistant_token(self, db, user, label, days=30):
        token = "ai2ai_at_" + secrets.token_urlsafe(32)
        db.add(AssistantToken(token_hash=sha256(token.encode()), user_id=user.id, label=label[:100],
                              expires_at=utcnow() + timedelta(days=max(1, min(int(days), 90)))))
        db.flush()
        return token

    def list_assistant_tokens(self, db, user):
        rows = db.execute(select(AssistantToken).where(AssistantToken.user_id == user.id)).scalars()
        return [{"id": t.token_hash[:16], "label": t.label, "revoked": t.revoked,
                 "expires_at": t.expires_at.isoformat() if t.expires_at else None} for t in rows]

    def revoke_assistant_token(self, db, user, token_id):
        for t in db.execute(select(AssistantToken).where(AssistantToken.user_id == user.id)).scalars():
            if t.token_hash.startswith(token_id) and len(token_id) >= 16:
                t.revoked = True
                return True
        raise EdgeError("token not found", 404)

    def end_session(self, db, token):
        s = db.get(EdgeSession, sha256(token.encode())) if token else None
        if s:
            db.delete(s)

    def assistant_user(self, db, token):
        at = db.get(AssistantToken, sha256(token.encode())) if token else None
        if at is None or at.revoked or at.expires_at is None or _aware(at.expires_at) < utcnow():
            return None
        u = db.get(EdgeUser, at.user_id)
        return u if u and u.is_active else None

    # ================= environment state (through the use case's connector) =================
    def load_estate(self, db) -> Environment:
        st = db.get(EstateState, 1)
        if st is None:
            e = self.connector.new_environment()
            db.add(EstateState(id=1, data=e.snapshot()))
            db.flush()
            return e
        return self.connector.new_environment(json.loads(json.dumps(st.data)))

    def save_estate(self, db, e: Environment):
        st = db.get(EstateState, 1)
        st.data = e.snapshot()
        db.flush()

    # ================= users, enrolment, passkeys, sessions =================
    def create_user(self, db, name, email, role):
        if role not in ("edge_admin", "approver"):
            raise EdgeError("role must be edge_admin or approver", 422)
        if db.execute(select(EdgeUser).where(EdgeUser.email == email.lower())).scalar_one_or_none():
            raise EdgeError("user exists", 409)
        u = EdgeUser(name=name, email=email.lower(), role=role)
        db.add(u)
        db.flush()
        return u

    def new_enrolment(self, db, user: EdgeUser, hours=24) -> str:
        code = secrets.token_urlsafe(18)
        db.add(Enrolment(code_hash=sha256(code.encode()), user_id=user.id, expires_at=utcnow() + timedelta(hours=hours)))
        db.flush()
        return code

    def _store_challenge(self, db, challenge: bytes, purpose, binding, user_id=None):
        db.query(Challenge).filter(Challenge.expires < time.time() - 60).delete(synchronize_session=False)
        db.add(Challenge(challenge=bytes_to_base64url(challenge), purpose=purpose, binding=binding, user_id=user_id,
                         expires=time.time() + CHALLENGE_TTL))
        db.flush()

    def _take_challenge(self, db, credential, purpose, binding):
        try:
            cd = json.loads(base64url_to_bytes(credential["response"]["clientDataJSON"]))
            ch = cd["challenge"]
        except Exception:
            raise EdgeError("malformed passkey response", 422)
        c = db.get(Challenge, ch)
        if c is None:
            raise EdgeError("unknown challenge", 403)
        if c.used:
            raise EdgeError("passkey response replayed (challenge already used)", 403)
        if c.purpose != purpose or c.binding != binding:
            raise EdgeError("passkey response was made for a different approval", 403)
        if time.time() > c.expires:
            raise EdgeError("approval ceremony expired", 403)
        c.used = True
        return c, base64url_to_bytes(ch)

    def enrol_options(self, db, code: str) -> str:
        enr = db.get(Enrolment, sha256(code.encode()))
        if enr is None or enr.used or _aware(enr.expires_at) < utcnow():
            raise EdgeError("enrolment code invalid or expired", 403)
        user = db.get(EdgeUser, enr.user_id)
        ch = os.urandom(32)
        self._store_challenge(db, ch, "register", enr.code_hash, user.id)
        opts = generate_registration_options(
            rp_id=self.s.rp_id, rp_name=f"{self.s.org_name} approvals", user_id=user.id.encode(), user_name=user.email,
            challenge=ch, authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED, user_verification=UserVerificationRequirement.REQUIRED))
        return options_to_json(opts)

    def enrol_finish(self, db, code: str, credential: dict):
        enr = db.get(Enrolment, sha256(code.encode()))
        if enr is None or enr.used:
            raise EdgeError("enrolment code invalid", 403)
        c, ch = self._take_challenge(db, credential, "register", enr.code_hash)
        try:
            v = verify_registration_response(credential=credential, expected_challenge=ch, expected_origin=self.s.origin,
                                             expected_rp_id=self.s.rp_id, require_user_verification=True)
        except Exception as exc:
            raise EdgeError(f"passkey registration rejected: {exc}", 403)
        db.add(PasskeyCred(credential_id=bytes_to_base64url(v.credential_id), user_id=enr.user_id,
                           public_key=bytes_to_base64url(v.credential_public_key), sign_count=v.sign_count))
        enr.used = True
        db.flush()

    def login_options(self, db) -> str:
        ch = os.urandom(32)
        self._store_challenge(db, ch, "login", "-")
        return options_to_json(generate_authentication_options(rp_id=self.s.rp_id, challenge=ch,
                                                              user_verification=UserVerificationRequirement.REQUIRED))

    def _verify_assertion(self, db, credential, expected_challenge, user_id=None) -> tuple:
        cred = db.get(PasskeyCred, credential.get("id") or credential.get("rawId") or "")
        if cred is None or (user_id and cred.user_id != user_id):
            raise EdgeError("unknown passkey", 403)
        user = db.get(EdgeUser, cred.user_id)
        if not user.is_active:
            raise EdgeError("user deactivated", 403)
        try:
            v = verify_authentication_response(
                credential=credential, expected_challenge=expected_challenge, expected_rp_id=self.s.rp_id,
                expected_origin=self.s.origin, credential_public_key=base64url_to_bytes(cred.public_key),
                credential_current_sign_count=cred.sign_count, require_user_verification=True)
        except Exception as exc:
            msg = str(exc)
            if "sign count" in msg.lower():
                msg = "sign counter went backwards - possible cloned authenticator"
            raise EdgeError(f"passkey rejected: {msg}", 403)
        cred.sign_count = v.new_sign_count
        return user, cred, v

    def login_finish(self, db, credential):
        c, ch = self._take_challenge(db, credential, "login", "-")
        user, _cred, _v = self._verify_assertion(db, credential, ch)
        token = secrets.token_urlsafe(32)
        s = EdgeSession(token_hash=sha256(token.encode()), user_id=user.id, csrf_token=secrets.token_urlsafe(32),
                        expires_at=utcnow() + timedelta(hours=8))
        db.add(s)
        db.flush()
        return token, s, user

    def session_user(self, db, token):
        if not token:
            return None, None
        s = db.get(EdgeSession, sha256(token.encode()))
        if s is None or _aware(s.expires_at) < utcnow():
            return None, None
        u = db.get(EdgeUser, s.user_id)
        return (u, s) if u and u.is_active else (None, None)

    def approval_options(self, db, user: EdgeUser, purpose: str, binding: str) -> str:
        creds = list(db.execute(select(PasskeyCred).where(PasskeyCred.user_id == user.id)).scalars())
        if not creds:
            raise EdgeError("register a passkey first", 409)
        ch = hashlib.sha256(canonical({"purpose": purpose, "binding": binding, "nonce": new_nonce()})).digest()
        self._store_challenge(db, ch, purpose, binding, user.id)
        return options_to_json(generate_authentication_options(
            rp_id=self.s.rp_id, challenge=ch, user_verification=UserVerificationRequirement.REQUIRED,
            allow_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(c.credential_id)) for c in creds]))

    def verify_approval(self, db, user: EdgeUser, credential, purpose: str, binding: str) -> dict:
        c, ch = self._take_challenge(db, credential, purpose, binding)
        if c.user_id != user.id:
            raise EdgeError("passkey ceremony belongs to a different user", 403)
        _u, cred, v = self._verify_assertion(db, credential, ch, user_id=user.id)
        return {"method": "webauthn", "credential_id": cred.credential_id, "user_verified": bool(v.user_verified),
                "sign_count": v.new_sign_count, "rp_id": self.s.rp_id, "binding": binding, "user": user.email}

    # ================= jobs (customer side) =================
    def draft_job(self, db, user: EdgeUser, bundle: dict, ticket: str, level: str, provider_cosign: bool = False,
                  agent_id: str = None):
        if not bundle and agent_id and self.fetch_listing:
            bundle = self.fetch_listing(agent_id)  # fetched from the centre, then verified like any other bundle
        ok, reasons, facts = verify_listing(bundle, self.centre_key["public_key"], self.centre_key["kid"],
                                            revoked=set(self.fetch_revocations()))
        if not ok:
            raise EdgeError("provider listing failed verification: " + "; ".join(reasons), 403)
        if level not in LEVEL_CLASSES:
            raise EdgeError("level must be D1 or D2", 422)
        if LEVEL_RANK[level] > LEVEL_RANK[facts["max_level"]]:
            raise EdgeError(f"agent is only listed up to {facts['max_level']}", 422)
        if self.connector.listing_id not in facts["connectors"]:
            raise EdgeError("agent does not support this environment's connector", 422)
        if not ticket or len(ticket) > 4000:
            raise EdgeError("describe the issue (up to 4000 characters)", 422)
        if provider_cosign and not facts["technician_keys"]:
            raise EdgeError("provider has no registered technician keys for co-signing", 422)
        now = time.time()
        wo = {"type": "WorkOrder", "wo_id": f"WO-{new_nonce()[:10]}", "created_by": "customer",
              "requester_org": self.s.org_id, "requester_name": self.s.org_name, "provider_org": facts["org_id"],
              "provider_name": facts["org_name"], "agent_id": facts["agent_id"], "agent_kid": facts["agent_kid"],
              "agent_version": facts["version"], "agent_build_digest": facts["build_digest"], "level": level,
              "allowed_classes": LEVEL_CLASSES[level], "ticket_digest": digest(ticket),
              "approvers": ["customer"] + (["provider-technician"] if provider_cosign else []),
              "window_start": now, "window_end": now + 3600 * 4, "max_cost": 0, "nonce": new_nonce()}
        job = Job(wo_id=wo["wo_id"], status="drafted", ticket=ticket, level=level, work_order=wo, listing_facts=facts,
                  created_by=user.id)
        db.add(job)
        db.flush()
        self.audit(db, job.id, "customer", "work_order.drafted",
                   f"{wo['wo_id']} {level} with verified provider {facts['org_name']}")
        return job

    def get_job(self, db, job_id) -> Job:
        job = db.get(Job, job_id)
        if job is None:
            raise EdgeError("job not found", 404)
        return job

    def approve_job(self, db, user: EdgeUser, job_id, credential):
        job = self.get_job(db, job_id)
        if job.status != "drafted":
            raise EdgeError(f"job is {job.status}", 409)
        evidence = self.verify_approval(db, user, credential, "work_order", digest(job.work_order))
        job.work_order_env = self.approver.sign(dict(job.work_order, approval_evidence=evidence))
        job.status = "approved"
        with self.estate_lock:
            job.seeded_state = self.load_estate(db).snapshot()
        self.audit(db, job.id, "customer", "work_order.approved",
                   f"passkey verified ({user.email}); classes {job.work_order['allowed_classes']}", "allow")
        self._notice(job, "JobNotice", "/api/v1/edge/jobs/notice", agent_id=job.listing_facts["agent_id"],
                     provider_org=job.listing_facts["org_id"], level=job.level)
        return job

    def kill(self, db, user: EdgeUser, job_id):
        job = self.get_job(db, job_id)
        if job.status in TERMINAL:
            raise EdgeError(f"job already {job.status}", 409)
        job.status = "canceled"
        for su in db.execute(select(StepUp).where(StepUp.job_id == job.id, StepUp.status == "pending")).scalars():
            su.status = "voided"
        self.audit(db, job.id, "customer", "kill_switch", f"{job.wo_id} revoked by {user.email}; tokens dead", "deny")
        if job.work_order_env:
            self._notice(job, "JobUpdate", "/api/v1/edge/jobs/update", status="canceled", outcome="killed by customer")
        return job

    def stepup_options(self, db, user, job_id, chash):
        su = db.get(StepUp, chash)
        if su is None or su.job_id != job_id or su.status != "pending":
            raise EdgeError("no pending approval with that hash", 404)
        return self.approval_options(db, user, "change", chash)

    def approve_stepup(self, db, user, job_id, chash, credential, technician_approval: dict = None):
        job = self.get_job(db, job_id)
        su = db.get(StepUp, chash)
        if su is None or su.job_id != job.id or su.status != "pending":
            raise EdgeError("no pending approval with that hash", 404)
        if job.status in TERMINAL:
            raise EdgeError(f"job is {job.status}", 409)
        evidence = self.verify_approval(db, user, credential, "change", chash)
        now = time.time()
        approvals = [self.approver.sign({"type": "StepUpApproval", "wo_id": job.wo_id, "command_hash": chash,
                                         "nonce": new_nonce(), "iat": now, "exp": now + APPROVAL_TTL,
                                         "approval_evidence": evidence})]
        if technician_approval:
            approvals.append(technician_approval)
        su.approvals = approvals
        su.status = "approved"
        self.audit(db, job.id, "customer", "step_up.approved", f"{su.op} {json.dumps(su.args)} (passkey)", "allow")

    def decline_stepup(self, db, user, job_id, chash):
        su = db.get(StepUp, chash)
        if su is None or su.job_id != job_id or su.status != "pending":
            raise EdgeError("no pending approval with that hash", 404)
        su.status = "declined"
        self.get_job(db, job_id).status = "working"
        self.audit(db, job_id, "customer", "step_up.declined", f"{su.op} {json.dumps(su.args)}", "deny")

    def rollback_last(self, db, user, job_id):
        job = self.get_job(db, job_id)
        change = db.execute(select(Change).where(Change.job_id == job.id, Change.status == "applied")
                            .order_by(Change.seq.desc()).limit(1)).scalar_one_or_none()
        if change is None:
            raise EdgeError("nothing to roll back", 409)
        with self.estate_lock:
            e = self.load_estate(db)
            if e.digest() != change.after_digest:
                self.audit(db, job.id, "customer", "rollback.refused", "environment changed since; review needed", "deny")
                raise EdgeError("the environment changed since this change; manual review needed", 409)
            e.restore(change.snapshot)
            self.save_estate(db, e)
        change.status = "rolled_back"
        self.audit(db, job.id, "customer", f"rollback {change.op}", f"restored to {change.before_digest[:12]}", "allow")
        amendment = None
        if job.receipt:
            amendment = self.broker.sign({"type": "ReceiptAmendment", "wo_id": job.wo_id,
                                          "receipt_digest": digest(job.receipt), "change_id": change.id,
                                          "action": "rolled_back", "by": user.email,
                                          "environment_digest_after": e.digest(),
                                          "audit_root": self.audit_root(db, job.id), "ts": time.time()})
            self.anchor(db, "amendment", amendment)
        return {"change_id": change.id, "amendment": amendment}

    def customer_view(self, db, job_id):
        job = self.get_job(db, job_id)
        ok, bad = self.verify_audit(db, job.id)
        return {
            "id": job.id, "wo_id": job.wo_id, "status": job.status, "level": job.level, "ticket": job.ticket,
            "work_order": job.work_order, "provider": job.listing_facts["org_name"],
            "agent": {"id": job.listing_facts["agent_id"], "version": job.listing_facts["version"]},
            "escalated": job.escalated, "escalation_reason": job.escalation_reason,
            "pending": [{"command_hash": s.command_hash, "op": s.op, "args": s.args, "diff": s.diff}
                        for s in db.execute(select(StepUp).where(StepUp.job_id == job.id, StepUp.status == "pending")).scalars()],
            "changes": [{"id": c.id, "op": c.op, "args": c.args, "status": c.status, "before": c.before_digest,
                         "after": c.after_digest} for c in db.execute(select(Change).where(Change.job_id == job.id)
                                                                      .order_by(Change.seq)).scalars()],
            "audit": [{"seq": e.seq, "actor": e.actor, "event": e.event, "detail": e.detail, "outcome": e.outcome}
                      for e in self.audit_entries(db, job.id)],
            "chain": {"ok": ok, "bad_seq": bad, "root": self.audit_root(db, job.id)},
            "receipt": job.receipt}

    # ================= agent side (signed requests + tokens) =================
    def _agent_verify(self, job: Job, req_env: dict) -> dict:
        f = job.listing_facts
        try:
            return verify_with_public(req_env, f["agent_public_key"], expected_kid=f["agent_kid"])
        except SignatureError as exc:
            raise EdgeError(f"request not signed by the job's agent ({exc})", 403)

    def _nonce_once(self, db, req):
        n, ts = req.get("nonce"), req.get("ts")
        if not isinstance(n, str) or not isinstance(ts, (int, float)):
            raise EdgeError("request needs nonce and ts", 422)
        if abs(time.time() - ts) > MAX_SKEW:
            raise EdgeError("stale request timestamp", 403)
        if db.get(SeenNonce, n):
            raise EdgeError("replayed request (nonce already used)", 403)
        # requests older than the skew window are refused anyway, so their nonces can be forgotten
        db.query(SeenNonce).filter(SeenNonce.seen_at < time.time() - 4 * MAX_SKEW).delete(synchronize_session=False)
        db.add(SeenNonce(nonce=n, seen_at=time.time()))
        db.flush()

    def _revocation_problem(self, facts: dict):
        """Re-checked at every token issuance (spec Part 2, DX-P-5), so a provider, agent or credential revoked after
        the Work Order was approved stops getting access within one token lifetime. Fails closed."""
        try:
            revoked = set(self.fetch_revocations())
        except Exception:
            return "could not check the provider's revocation status; access refused (fail closed)"
        ids = [facts.get(k) for k in ("agent_id", "org_id", "org_kid", "agent_kid")]
        creds = facts.get("credentials")
        if not all(isinstance(i, str) and i for i in ids) or not isinstance(creds, dict):
            return "the job's verified listing is incomplete; access refused (fail closed)"
        if any(i in revoked for i in ids):
            return "the provider or its agent has been revoked since this Work Order was approved"
        missing = required_credentials_met({kind for cid, kind in creds.items() if cid not in revoked})
        if missing:
            return "a provider credential has been revoked since approval; missing " + ", ".join(missing)
        return None

    def issue_token(self, db, req_env: dict):
        wo_id = (req_env.get("payload") or {}).get("wo_id")
        job = db.execute(select(Job).where(Job.wo_id == str(wo_id))).scalar_one_or_none()
        if job is None:
            raise EdgeError("unknown work order", 404)
        req = self._agent_verify(job, req_env)
        self._nonce_once(db, req)
        if req.get("type") != "TokenRequest":
            raise EdgeError("not a token request", 422)
        if job.status not in ("approved", "working", "input-required"):
            self.audit(db, job.id, "customer-idp", "token.refused", f"job is {job.status}", "deny")
            raise EdgeError(f"job is {job.status}; no access", 403)
        problem = self._revocation_problem(job.listing_facts)
        if problem:
            self.audit(db, job.id, "customer-idp", "token.refused", problem, "deny")
            raise EdgeError(problem, 403)
        wo = verify_with_public(job.work_order_env, self.approver.public_b64, expected_kid=self.approver.kid)
        now = time.time()
        if not wo["window_start"] <= now <= wo["window_end"]:
            raise EdgeError("outside the approved time window", 403)
        token = self.idp.sign({"type": "AccessToken", "jti": new_nonce(), "aud": "customer-broker",
                               "sub": job.listing_facts["agent_kid"], "wo_id": job.wo_id, "level": job.level,
                               "allowed_classes": wo["allowed_classes"], "iat": now, "exp": now + TOKEN_TTL})
        if job.status == "approved":
            job.status = "working"
        self.audit(db, job.id, "customer-idp", "token.issued", f"{TOKEN_TTL}s token bound to the agent key", "allow")
        return token

    def _authenticate(self, db, token_env, req_env):
        try:
            token = verify_with_public(token_env, self.idp.public_b64, expected_kid=self.idp.kid)
        except SignatureError as exc:
            raise EdgeError(f"token not issued by this customer's IdP ({exc})", 401)
        if token.get("aud") != "customer-broker":
            raise EdgeError("token audience mismatch", 401)
        job = db.execute(select(Job).where(Job.wo_id == token["wo_id"])).scalar_one_or_none()
        if job is None:
            raise EdgeError("unknown work order", 404)
        op = (req_env.get("payload") or {}).get("op", "?")

        def refuse(reason, status):
            self.audit(db, job.id, "agent", f"call.denied {op}", reason, "deny")
            raise EdgeError(reason, status)

        if job.status == "canceled":
            refuse("Work Order revoked by the customer (kill switch)", 403)
        if job.status in TERMINAL:
            refuse(f"job is {job.status}", 403)
        if time.time() > token["exp"]:
            refuse("token expired", 401)
        if req_env.get("kid") != token["sub"]:
            refuse("request not signed by the token holder", 403)
        try:
            req = self._agent_verify(job, req_env)
        except EdgeError as exc:
            refuse(str(exc), 403)
        if req.get("wo_id") != job.wo_id:
            refuse("request is for a different work order", 403)
        try:
            self._nonce_once(db, req)
        except EdgeError as exc:
            refuse(str(exc), exc.status)
        return token, req, job

    def _deny(self, db, job, op, reason):
        self.audit(db, job.id, "agent", f"call.denied {op}", reason, "deny")
        return {"ok": False, "reason": reason}

    def call(self, db, token_env, req_env):
        token, req, job = self._authenticate(db, token_env, req_env)
        op, args = str(req.get("op", "")), req.get("args") or {}
        if not isinstance(args, dict):
            return self._deny(db, job, op, "args must be an object")
        cls = self.connector.class_of(op)
        if cls == "egress":
            return self._deny(db, job, op, "outbound traffic blocked (egress allow-list is empty)")
        if cls not in token["allowed_classes"]:
            return self._deny(db, job, op, f"'{cls}' action not permitted; Work Order allows "
                                           f"{token['allowed_classes']} at {token['level']}")
        if cls == "reversible":
            h = command_hash(job.wo_id, op, args)
            su = db.get(StepUp, h)
            if su is None:
                diff = f"{self.connector.describe(op)} Details: {json.dumps(args, sort_keys=True)}"
                db.add(StepUp(command_hash=h, job_id=job.id, op=op, args=args, diff=diff, created=time.time()))
                job.status = "input-required"
                self.audit(db, job.id, "customer-broker", f"approval.required {op}", diff)
                self.notify(db, job.id, "approval.needed", f"{job.listing_facts['org_name']} asks to: {diff}")
            return {"ok": False, "approval_required": True, "command_hash": h,
                    "status": su.status if su else "pending"}
        with self.estate_lock:
            e = self.load_estate(db)
            before = e.digest()
            try:
                data = self.connector.run(e, op, args)
            except OpError as exc:
                self.audit(db, job.id, "agent", f"call.failed {op}", str(exc), "info")
                return {"ok": False, "reason": f"operation failed: {exc}"}
            if e.digest() != before:  # a read must never change anything
                raise EdgeError("connector fault: read changed the environment", 500)
        self.audit(db, job.id, "agent", f"call.allowed {op}", "class=read", "allow")
        return {"ok": True, "class": cls, "content": wrap_untrusted(data)}

    def _check_approvals(self, job, su, now):
        wo = job.work_order
        required = {self.approver.kid}
        tech_keys = job.listing_facts.get("technician_keys", {})
        if "provider-technician" in wo["approvers"]:
            required.add("provider-technician")
        signed = set()
        for env in su.approvals or []:
            kid = env.get("kid", "")
            pub = self.approver.public_b64 if kid == self.approver.kid else tech_keys.get(kid)
            if pub is None:
                return "approval not signed by an authorised human"
            try:
                a = verify_with_public(env, pub, expected_kid=kid)
            except SignatureError:
                return "approval signature invalid"
            if a.get("type") != "StepUpApproval" or a.get("wo_id") != job.wo_id:
                return "approval is for a different work order"
            if a.get("command_hash") != su.command_hash:
                return "approval does not match this exact command"
            if now > a.get("exp", 0):
                return "approval expired"
            if kid == self.approver.kid and not (a.get("approval_evidence") or {}).get("user_verified"):
                return "customer approval lacks a verified passkey"
            signed.add("provider-technician" if kid in tech_keys else kid)
        missing = required - signed
        return ("missing approval from " + ", ".join(sorted(k.split(":")[0] for k in missing))) if missing else None

    def change(self, db, token_env, req_env):
        token, req, job = self._authenticate(db, token_env, req_env)
        op, args = str(req.get("op", "")), req.get("args") or {}
        cls = self.connector.class_of(op)
        if cls != "reversible" or cls not in token["allowed_classes"]:
            return self._deny(db, job, op, f"'{cls}' actions cannot be executed through step-up approval at {token['level']}")
        h = command_hash(job.wo_id, op, args)
        su = db.get(StepUp, h)
        if su is None:
            return self._deny(db, job, op, "no approval request exists for this exact command")
        if su.status == "pending":
            return {"ok": False, "waiting": True, "reason": "waiting for the customer's approval"}
        if su.status != "approved":
            return self._deny(db, job, op, f"approval {su.status}")
        reason = self._check_approvals(job, su, time.time())
        if reason:
            return self._deny(db, job, op, reason)
        su.status = "used"
        with self.estate_lock:
            e = self.load_estate(db)
            snap, before = e.snapshot(), e.digest()
            self.audit(db, job.id, "customer-broker", "snapshot.taken", f"before {op}: {before[:12]}")
            ok, err = True, ""
            try:
                self.connector.run(e, op, args)
            except OpError as exc:
                ok, err = False, str(exc)
            if self.fail_next_postcheck:
                ok, err, self.fail_next_postcheck = False, "post-check failed (simulated)", False
            if not ok:
                e.restore(snap)
            self.save_estate(db, e)
            seq = len(list(db.execute(select(Change).where(Change.job_id == job.id)).scalars()))
            c = Change(job_id=job.id, seq=seq, op=op, args=args, command_hash=h, before_digest=before,
                       after_digest=e.digest(), snapshot=snap, status="applied" if ok else "rolled_back")
            db.add(c)
        job.status = "working"
        if ok:
            self.audit(db, job.id, "agent", f"change.applied {op}", su.diff, "allow")
        else:
            self.audit(db, job.id, "customer-broker", f"change.rolled_back {op}", f"{err}; restored automatically", "deny")
        return {"ok": ok, "change_id": c.id, "reason": "" if ok else f"{err}; rolled back"}

    def escalate(self, db, token_env, req_env):
        token, req, job = self._authenticate(db, token_env, req_env)
        job.escalated, job.escalation_reason = True, str(req.get("reason", ""))[:2000]
        self.audit(db, job.id, "agent", "escalated_to_human", job.escalation_reason, "info")
        self.notify(db, job.id, "job.escalated", f"The agent handed this to a person: {job.escalation_reason}")
        return {"ok": True}

    def complete(self, db, token_env, req_env):
        token, req, job = self._authenticate(db, token_env, req_env)
        if req.get("type") != "CompletionStatement":
            raise EdgeError("not a completion statement", 422)
        for su in db.execute(select(StepUp).where(StepUp.job_id == job.id, StepUp.status.in_(("pending", "approved")))).scalars():
            su.status = "voided"
        changes = list(db.execute(select(Change).where(Change.job_id == job.id).order_by(Change.seq)).scalars())
        allowed = [e.event.split(" ", 1)[1] for e in self.audit_entries(db, job.id) if e.event.startswith("call.allowed")]
        denied = [e.event.split(" ", 1)[1] for e in self.audit_entries(db, job.id) if e.event.startswith("call.denied")]
        job.status = "completed"
        job.provider_statement = req_env
        self.audit(db, job.id, "agent", "job.completed", str(req.get("summary", ""))[:500], "info")
        with self.estate_lock:
            end_digest = self.load_estate(db).digest()
        job.receipt = self.broker.sign({
            "type": "Receipt", "wo_id": job.wo_id, "job_id": job.id, "provider_statement": req_env,
            "operations_allowed": allowed, "operations_denied": denied, "escalated": job.escalated,
            "changes_made": [{"id": c.id, "op": c.op, "args": c.args, "before": c.before_digest, "after": c.after_digest}
                             for c in changes if c.status == "applied"],
            "changes_rolled_back": [{"id": c.id, "op": c.op} for c in changes if c.status == "rolled_back"],
            "environment_digest_end": end_digest, "audit_root": self.audit_root(db, job.id), "issued": time.time()})
        self.anchor(db, "receipt", job.receipt)
        self.notify(db, job.id, "job.completed", f"{job.wo_id} finished; signed receipt issued")
        self._notice(job, "JobUpdate", "/api/v1/edge/jobs/update", status="completed",
                     outcome="escalated" if job.escalated else "completed", escalated=job.escalated,
                     changes_count=sum(1 for c in changes if c.status == "applied"), receipt_digest=digest(job.receipt))
        return {"ok": True, "receipt": job.receipt}

    def agent_job(self, db, token_env, req_env):
        token, req, job = self._authenticate(db, token_env, req_env)
        return {"wo_id": job.wo_id, "ticket": job.ticket, "level": job.level, "allowed_classes": token["allowed_classes"],
                "operations": self.connector.catalogue(),
                "notes": "Reads return customer data wrapped as untrusted. Reversible changes need the customer's "
                         "approval: request them with /agent/v1/call, then submit with /agent/v1/change once approved."}
