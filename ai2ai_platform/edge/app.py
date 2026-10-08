"""Customer edge HTTP app (one per customer, its own process, keys and database).

- Customer people: passkey-only sign-in, session cookie (HttpOnly, SameSite=Strict) + CSRF on every change.
- Agents: no sessions. Signed requests (agent key from the verified listing) + short-lived tokens from this edge's IdP.
"""
import hmac
import os
from dataclasses import dataclass, field

from fastapi import Body, Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from ..core.keystore import KeyStore
from ..db import make_engine, make_session_factory
from .models import Job
from .service import EdgeError, EdgeService

EDGE_COOKIE = "ai2ai_edge"
UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}


@dataclass
class EdgeSettings:
    data_dir: str
    org_id: str
    org_name: str
    base_url: str = "http://localhost:8810"
    rp_id: str = "localhost"
    database_url: str = ""
    centre_url: str = "http://localhost:8800"
    usecase: str = field(default_factory=lambda: os.environ.get("AI2AI_USECASE", "it_support"))  # environment connector
    sim_controls: bool = False  # test/demo only: seed scenarios and judge outcomes
    https: bool = False

    def __post_init__(self):
        os.makedirs(self.data_dir, exist_ok=True)
        if not self.database_url:
            self.database_url = "sqlite:///" + os.path.join(self.data_dir, "edge.db").replace("\\", "/")

    @property
    def origin(self) -> str:
        return self.base_url.rstrip("/")


def create_edge_app(settings: EdgeSettings, centre_key: dict, revocations_fetcher, centre_notifier=None,
                    listing_fetcher=None) -> FastAPI:
    app = FastAPI(title=f"AI2AI customer edge - {settings.org_name}", docs_url=None, redoc_url=None, openapi_url=None)
    from .migrate import migrate_edge
    migrate_edge(settings.database_url)
    engine = make_engine(settings.database_url)
    sf = make_session_factory(engine)
    ks = KeyStore(settings.data_dir)
    signers = {"idp": ks.load_or_create("idp", "customer-idp"),
               "approver": ks.load_or_create("approver", "customer-approver"),
               "broker": ks.load_or_create("broker", "customer-broker")}
    svc = EdgeService(settings, sf, signers, centre_key, revocations_fetcher, centre_notifier, listing_fetcher)
    app.state.svc, app.state.engine, app.state.session_factory, app.state.settings = svc, engine, sf, settings
    from ..centre.security import RateLimiter
    app.state.ceremony_limiter = RateLimiter(30)

    def limit(request: Request):
        ip = request.client.host if request.client else "?"
        if not app.state.ceremony_limiter.allow(ip):
            raise HTTPException(429, "too many attempts; wait a minute")

    @app.exception_handler(EdgeError)
    async def edge_error(request, exc: EdgeError):
        return JSONResponse({"detail": str(exc)}, status_code=exc.status)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        if request.method in UNSAFE:
            if not request.headers.get("content-type", "").startswith("application/json"):
                return JSONResponse({"detail": "unsupported content type"}, status_code=415)
            origin = request.headers.get("origin")
            if origin and origin.rstrip("/") != settings.origin:
                return JSONResponse({"detail": "cross-origin request refused"}, status_code=403)
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Cache-Control", "no-store")
        resp.headers.setdefault("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
        return resp

    def db_dep():
        db = sf()
        try:
            yield db
            db.commit()
        except EdgeError:
            db.commit()  # keep denial records, consumed challenges and nonces
            raise
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def user_dep(request: Request, db=Depends(db_dep)):
        u, s = svc.session_user(db, request.cookies.get(EDGE_COOKIE))
        if u is None:
            raise HTTPException(401, "sign in with your passkey")
        request.state.edge_session = s
        return u

    def csrf_user(request: Request, u=Depends(user_dep)):
        sent = request.headers.get("X-CSRF-Token", "")
        if not hmac.compare_digest(sent, request.state.edge_session.csrf_token):
            raise HTTPException(403, "CSRF token missing or invalid")
        return u

    def admin_csrf(u=Depends(csrf_user)):
        if u.role != "edge_admin":
            raise HTTPException(403, "edge admin only")
        return u

    # ----- enrolment + passkey sign-in -----
    @app.post("/edge/api/enrol/options", dependencies=[Depends(limit)])
    def enrol_options(body: dict = Body(...), db=Depends(db_dep)):
        return {"options": svc.enrol_options(db, str(body.get("code", "")))}

    @app.post("/edge/api/enrol/finish")
    def enrol_finish(body: dict = Body(...), db=Depends(db_dep)):
        svc.enrol_finish(db, str(body.get("code", "")), body.get("credential") or {})
        return {"ok": True}

    @app.post("/edge/api/login/options", dependencies=[Depends(limit)])
    def login_options(db=Depends(db_dep)):
        return {"options": svc.login_options(db)}

    @app.post("/edge/api/login/finish", dependencies=[Depends(limit)])
    def login_finish(body: dict = Body(...), db=Depends(db_dep)):
        token, s, user = svc.login_finish(db, body.get("credential") or {})
        resp = JSONResponse({"csrf_token": s.csrf_token, "user": {"name": user.name, "email": user.email,
                                                                  "role": user.role}})
        resp.set_cookie(EDGE_COOKIE, token, httponly=True, samesite="strict", secure=settings.https, path="/")
        return resp

    @app.get("/edge/api/me")
    def me(request: Request, u=Depends(user_dep)):
        return {"name": u.name, "email": u.email, "role": u.role, "csrf_token": request.state.edge_session.csrf_token,
                "org": settings.org_name}

    @app.post("/edge/api/users")
    def add_user(body: dict = Body(...), u=Depends(admin_csrf), db=Depends(db_dep)):
        new = svc.create_user(db, str(body.get("name", "")), str(body.get("email", "")), str(body.get("role", "")))
        return {"id": new.id, "enrolment_code": svc.new_enrolment(db, new)}

    # ----- jobs (customer) -----
    @app.post("/edge/api/jobs", status_code=201)
    def draft(body: dict = Body(...), u=Depends(csrf_user), db=Depends(db_dep)):
        job = svc.draft_job(db, u, body.get("bundle") or {}, str(body.get("ticket", "")), str(body.get("level", "")),
                            bool(body.get("provider_cosign")), agent_id=body.get("agent_id"))
        return {"id": job.id, "work_order": job.work_order}

    @app.get("/edge/api/jobs")
    def jobs(u=Depends(user_dep), db=Depends(db_dep)):
        from sqlalchemy import select
        return [{"id": j.id, "wo_id": j.wo_id, "status": j.status, "level": j.level, "ticket": j.ticket[:120],
                 "provider": j.listing_facts["org_name"]}
                for j in db.execute(select(Job).order_by(Job.created_at.desc())).scalars()]

    @app.get("/edge/api/jobs/{job_id}")
    def job(job_id: str, u=Depends(user_dep), db=Depends(db_dep)):
        return svc.customer_view(db, job_id)

    @app.post("/edge/api/jobs/{job_id}/approve/options")
    def approve_options(job_id: str, u=Depends(csrf_user), db=Depends(db_dep)):
        from ..core.crypto import digest
        return {"options": svc.approval_options(db, u, "work_order", digest(svc.get_job(db, job_id).work_order))}

    @app.post("/edge/api/jobs/{job_id}/approve")
    def approve(job_id: str, body: dict = Body(...), u=Depends(csrf_user), db=Depends(db_dep)):
        svc.approve_job(db, u, job_id, body.get("credential") or {})
        return {"ok": True}

    @app.post("/edge/api/jobs/{job_id}/stepups/{chash}/options")
    def su_options(job_id: str, chash: str, u=Depends(csrf_user), db=Depends(db_dep)):
        return {"options": svc.stepup_options(db, u, job_id, chash)}

    @app.post("/edge/api/jobs/{job_id}/stepups/{chash}/approve")
    def su_approve(job_id: str, chash: str, body: dict = Body(...), u=Depends(csrf_user), db=Depends(db_dep)):
        svc.approve_stepup(db, u, job_id, chash, body.get("credential") or {}, body.get("technician_approval"))
        return {"ok": True}

    @app.post("/edge/api/jobs/{job_id}/stepups/{chash}/decline")
    def su_decline(job_id: str, chash: str, u=Depends(csrf_user), db=Depends(db_dep)):
        svc.decline_stepup(db, u, job_id, chash)
        return {"ok": True}

    @app.post("/edge/api/jobs/{job_id}/kill")
    def kill(job_id: str, u=Depends(csrf_user), db=Depends(db_dep)):
        svc.kill(db, u, job_id)
        return {"ok": True}

    @app.post("/edge/api/jobs/{job_id}/rollback")
    def rollback(job_id: str, u=Depends(csrf_user), db=Depends(db_dep)):
        return svc.rollback_last(db, u, job_id)

    # ----- notifications + assistant tokens (the customer's own AI can draft and track, never approve) -----
    @app.get("/edge/api/notifications")
    def notifications(u=Depends(user_dep), db=Depends(db_dep)):
        return svc.notifications(db)

    @app.post("/edge/api/assistant-tokens", status_code=201)
    def new_token(body: dict = Body(...), u=Depends(csrf_user), db=Depends(db_dep)):
        return {"token": svc.new_assistant_token(db, u, str(body.get("label", "assistant")), body.get("days", 30))}

    @app.get("/edge/api/assistant-tokens")
    def list_tokens(u=Depends(user_dep), db=Depends(db_dep)):
        return svc.list_assistant_tokens(db, u)

    @app.post("/edge/api/assistant-tokens/{token_id}/revoke")
    def revoke_token(token_id: str, u=Depends(csrf_user), db=Depends(db_dep)):
        svc.revoke_assistant_token(db, u, token_id)
        return {"ok": True}

    @app.post("/edge/api/logout")
    def logout(request: Request, u=Depends(csrf_user), db=Depends(db_dep)):
        svc.end_session(db, request.cookies.get(EDGE_COOKIE))
        resp = JSONResponse({"ok": True})
        resp.delete_cookie(EDGE_COOKIE, path="/")
        return resp

    def assistant_dep(request: Request, db=Depends(db_dep)):
        auth = request.headers.get("Authorization", "")
        u = svc.assistant_user(db, auth[7:] if auth.startswith("Bearer ") else "")
        if u is None:
            raise HTTPException(401, "assistant token missing or revoked")
        return u

    @app.post("/edge/api/assistant/jobs", status_code=201)
    def assistant_draft(body: dict = Body(...), u=Depends(assistant_dep), db=Depends(db_dep)):
        job = svc.draft_job(db, u, {}, str(body.get("ticket", "")), str(body.get("level", "D2")),
                            agent_id=str(body.get("agent_id", "")))
        return {"id": job.id, "wo_id": job.wo_id, "status": job.status,
                "approve_at": f"{settings.origin}/edge/jobs/{job.id}"}

    @app.get("/edge/api/assistant/jobs/{job_id}")
    def assistant_job(job_id: str, u=Depends(assistant_dep), db=Depends(db_dep)):
        v = svc.customer_view(db, job_id)
        return {k: v[k] for k in ("id", "wo_id", "status", "level", "provider", "escalated", "escalation_reason",
                                  "pending", "changes", "receipt")}

    # ----- simulator controls (test/demo only) -----
    @app.post("/edge/api/sim/reset")
    def sim_reset(body: dict = Body(...), u=Depends(admin_csrf), db=Depends(db_dep)):
        if not settings.sim_controls:
            raise HTTPException(404, "not found")
        con = svc.connector
        scenarios = getattr(con, "scenarios", {})
        e = con.new_environment()
        sid = body.get("scenario")
        if sid:
            if sid not in scenarios:
                raise HTTPException(422, "unknown scenario")
            scenarios[sid].seed(e)
        for inj in body.get("injections") or []:
            if not hasattr(con, "plant_injection"):
                raise HTTPException(422, "this use case has no injection slots")
            con.plant_injection(e, str(inj["text"]), str(inj["slot"]))
        with svc.estate_lock:
            svc.load_estate(db)
            svc.save_estate(db, e)
        return {"ticket": scenarios[sid].ticket if sid else None}

    @app.get("/edge/api/sim/judge/{job_id}")
    def sim_judge(job_id: str, scenario: str, u=Depends(user_dep), db=Depends(db_dep)):
        if not settings.sim_controls:
            raise HTTPException(404, "not found")
        j = svc.get_job(db, job_id)
        with svc.estate_lock:
            final = svc.load_estate(db)
        scenarios = getattr(svc.connector, "scenarios", {})
        if scenario not in scenarios:
            raise HTTPException(422, "unknown scenario")
        return scenarios[scenario].judge(j.seeded_state, final, j.escalated)

    # ----- agents -----
    @app.post("/agent/v1/token")
    def agent_token(body: dict = Body(...), db=Depends(db_dep)):
        return {"token": svc.issue_token(db, body.get("request") or {})}

    def _agent(fn):
        def handler(body: dict = Body(...), db=Depends(db_dep)):
            return fn(db, body.get("token") or {}, body.get("request") or {})
        return handler

    app.post("/agent/v1/job")(_agent(svc.agent_job))
    app.post("/agent/v1/call")(_agent(svc.call))
    app.post("/agent/v1/change")(_agent(svc.change))
    app.post("/agent/v1/escalate")(_agent(svc.escalate))
    app.post("/agent/v1/complete")(_agent(svc.complete))

    # ----- pages (the customer's own UI; ticket text and approvals never leave this edge) -----
    from fastapi.responses import RedirectResponse
    from fastapi.staticfiles import StaticFiles
    from fastapi.templating import Jinja2Templates
    here = os.path.dirname(os.path.abspath(__file__))
    templates = Jinja2Templates(directory=os.path.join(here, "templates"))
    app.mount("/edge/static", StaticFiles(directory=os.path.join(here, "static")), name="edge-static")

    def page(request: Request, name: str, db, **ctx):
        u, s = svc.session_user(db, request.cookies.get(EDGE_COOKIE))
        if u is None:
            return RedirectResponse("/edge/login", status_code=303)
        return templates.TemplateResponse(request, name, dict(ctx, user=u, csrf=s.csrf_token, org=settings.org_name))

    @app.get("/edge/login")
    def login_page(request: Request):
        return templates.TemplateResponse(request, "login.html", {"title": "Sign in", "org": settings.org_name})

    @app.get("/edge/enrol")
    def enrol_page(request: Request, code: str = ""):
        return templates.TemplateResponse(request, "enrol.html", {"title": "Set up passkey", "org": settings.org_name,
                                                                  "code": code})

    @app.get("/edge/")
    def jobs_page(request: Request, db=Depends(db_dep)):
        return page(request, "jobs.html", db, title="Jobs")

    @app.get("/edge/new")
    def new_page(request: Request, agent: str = "", level: str = "D2", db=Depends(db_dep)):
        return page(request, "new.html", db, title="New job", agent=agent, level=level)

    @app.get("/edge/jobs/{job_id}")
    def job_page(job_id: str, request: Request, db=Depends(db_dep)):
        return page(request, "job.html", db, title="Job", job_id=job_id)

    @app.get("/edge/.well-known/keys")
    def keys():
        return {k: {"kid": s.kid, "public_key": s.public_b64} for k, s in signers.items()}

    @app.get("/healthz")
    def healthz():
        return {"ok": True, "org": settings.org_name}

    return app
