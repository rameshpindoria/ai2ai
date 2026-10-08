"""Platform centre: accounts, orgs, admin (M1). Later milestones add providers, catalogue, matching, jobs index."""
import os

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from ..config import Settings
from ..db import make_engine, make_session_factory, utcnow
from .models import ADMIN_ROLES, ROLES_BY_KIND, Org, User
from .security import (SESSION_COOKIE, Principal, RateLimiter, _DUMMY_HASH, _aware, audit, check_password,
                       create_session, current_principal, end_session, get_db, hash_password, password_problems,
                       require_csrf, require_roles, require_roles_csrf, verify_audit_chain)

HERE = os.path.dirname(os.path.abspath(__file__))
UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}
ALLOWED_TYPES = ("application/json", "application/x-www-form-urlencoded", "multipart/form-data")


# ----- request bodies -----
class SignupIn(BaseModel):
    org_name: str = Field(min_length=2, max_length=200)
    org_kind: str
    business_reg: str | None = Field(default=None, max_length=20)
    name: str = Field(min_length=1, max_length=200)
    email: str = Field(min_length=3, max_length=254)
    password: str


class LoginIn(BaseModel):
    email: str
    password: str


class NewUserIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    email: str = Field(min_length=3, max_length=254)
    role: str
    password: str


def _norm_email(e: str) -> str:
    e = e.strip().lower()
    if "@" not in e or e.startswith("@") or e.endswith("@"):
        raise HTTPException(422, "invalid email")
    return e


def _user_json(u: User, org: Org) -> dict:
    return {"id": u.id, "name": u.name, "email": u.email, "role": u.role,
            "org": {"id": org.id, "name": org.name, "kind": org.kind, "status": org.status}}


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    app = FastAPI(title="AI2AI Platform Centre", docs_url=None, redoc_url=None, openapi_url=None)
    engine = make_engine(settings.database_url)
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = make_session_factory(engine)
    app.state.login_limiter = RateLimiter(settings.login_rate_per_minute)
    from ..core.keystore import KeyStore
    from . import jobs, providers
    app.state.centre_signer = KeyStore(settings.data_dir).load_or_create("centre", "centre")
    app.include_router(providers.router)
    app.include_router(jobs.router)
    templates = Jinja2Templates(directory=os.path.join(HERE, "templates"))
    from fastapi.staticfiles import StaticFiles
    app.mount("/static", StaticFiles(directory=os.path.join(HERE, "static")), name="static")

    @app.middleware("http")
    async def guard(request: Request, call_next):
        if request.method in UNSAFE:
            ctype = request.headers.get("content-type", "")
            if not ctype.startswith(ALLOWED_TYPES):
                return JSONResponse({"detail": "unsupported content type"}, status_code=415)
            origin = request.headers.get("origin")
            if origin and origin.rstrip("/") not in settings.allowed_origins:
                return JSONResponse({"detail": "cross-origin request refused"}, status_code=403)
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        resp.headers.setdefault("Content-Security-Policy",
                                "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
        resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    def set_session_cookie(resp, token):
        resp.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="strict", secure=settings.https,
                        max_age=settings.session_hours * 3600, path="/")

    # ----- auth API -----
    @app.post("/api/v1/auth/signup", status_code=201)
    def signup(body: SignupIn, db=Depends(get_db)):
        if body.org_kind not in ("customer", "provider"):
            raise HTTPException(422, "org_kind must be customer or provider")
        email = _norm_email(body.email)
        probs = password_problems(body.password, settings.min_password_length)
        if probs:
            raise HTTPException(422, "password needs " + ", ".join(probs))
        if db.execute(select(User).where(User.email == email)).scalar_one_or_none():
            raise HTTPException(409, "an account with this email already exists")
        org = Org(name=body.org_name.strip(), kind=body.org_kind, business_reg=(body.business_reg or None))
        db.add(org)
        db.flush()
        role = "customer_admin" if body.org_kind == "customer" else "provider_admin"
        user = User(org_id=org.id, email=email, name=body.name.strip(), role=role,
                    password_hash=hash_password(body.password))
        db.add(user)
        db.commit()
        audit(db, "org.signup", user, org.id, kind=org.kind)
        return {"org_id": org.id, "user_id": user.id}

    @app.post("/api/v1/auth/login")
    def login(body: LoginIn, request: Request, db=Depends(get_db)):
        ip = request.client.host if request.client else "?"
        if not app.state.login_limiter.allow(ip):
            raise HTTPException(429, "too many sign-in attempts; wait a minute")
        email = body.email.strip().lower()
        user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
        if user is None:
            check_password(_DUMMY_HASH, body.password)  # equalise timing for unknown accounts
            raise HTTPException(401, "email or password is wrong")
        if user.locked_until and _aware(user.locked_until) > utcnow():
            raise HTTPException(423, "account locked after repeated failures; try again later")
        if not check_password(user.password_hash, body.password) or not user.is_active:
            user.failed_logins += 1
            if user.failed_logins >= settings.max_failed_logins:
                from datetime import timedelta
                user.locked_until = utcnow() + timedelta(minutes=settings.lockout_minutes)
                user.failed_logins = 0
                db.commit()
                audit(db, "user.locked", None, user.org_id, user=user.id)
                raise HTTPException(423, "account locked after repeated failures; try again later")
            db.commit()
            raise HTTPException(401, "email or password is wrong")
        user.failed_logins, user.locked_until = 0, None
        db.commit()
        org = db.get(Org, user.org_id)
        if org.status != "active":
            raise HTTPException(403, "organisation suspended")
        token, s = create_session(db, user, settings.session_hours, ip)
        resp = JSONResponse({"csrf_token": s.csrf_token, "user": _user_json(user, org)})
        set_session_cookie(resp, token)
        audit(db, "user.login", user, org.id)
        return resp

    @app.post("/api/v1/auth/logout")
    def logout(request: Request, p: Principal = Depends(require_csrf), db=Depends(get_db)):
        end_session(db, request.cookies.get(SESSION_COOKIE))
        resp = JSONResponse({"ok": True})
        resp.delete_cookie(SESSION_COOKIE, path="/")
        return resp

    @app.get("/api/v1/me")
    def me(p: Principal = Depends(current_principal)):
        return dict(_user_json(p.user, p.org), csrf_token=p.session.csrf_token)

    # ----- org user management (org admins, own org only) -----
    @app.get("/api/v1/orgs/me/users")
    def list_users(p: Principal = Depends(require_roles(*ADMIN_ROLES)), db=Depends(get_db)):
        rows = db.execute(select(User).where(User.org_id == p.org.id).order_by(User.created_at)).scalars()
        return [{"id": u.id, "name": u.name, "email": u.email, "role": u.role, "active": u.is_active} for u in rows]

    @app.post("/api/v1/orgs/me/users", status_code=201)
    def add_user(body: NewUserIn, p: Principal = Depends(require_roles_csrf(*ADMIN_ROLES)), db=Depends(get_db)):
        if body.role not in ROLES_BY_KIND[p.org.kind]:
            raise HTTPException(422, f"role must be one of {ROLES_BY_KIND[p.org.kind]}")
        email = _norm_email(body.email)
        probs = password_problems(body.password, settings.min_password_length)
        if probs:
            raise HTTPException(422, "password needs " + ", ".join(probs))
        if db.execute(select(User).where(User.email == email)).scalar_one_or_none():
            raise HTTPException(409, "an account with this email already exists")
        u = User(org_id=p.org.id, email=email, name=body.name.strip(), role=body.role,
                 password_hash=hash_password(body.password))
        db.add(u)
        db.commit()
        audit(db, "user.added", p.user, p.org.id, user=u.id, role=u.role)
        return {"id": u.id}

    @app.post("/api/v1/orgs/me/users/{user_id}/deactivate")
    def deactivate_user(user_id: str, p: Principal = Depends(require_roles_csrf(*ADMIN_ROLES)), db=Depends(get_db)):
        u = db.get(User, user_id)
        if u is None or u.org_id != p.org.id:  # never reveal other orgs' users
            raise HTTPException(404, "user not found")
        if u.id == p.user.id:
            raise HTTPException(422, "you cannot deactivate yourself")
        u.is_active = False
        db.commit()
        audit(db, "user.deactivated", p.user, p.org.id, user=u.id)
        return {"ok": True}

    # ----- platform admin -----
    @app.get("/api/v1/admin/orgs")
    def admin_orgs(p: Principal = Depends(require_roles("platform_admin")), db=Depends(get_db)):
        counts = dict(db.execute(select(User.org_id, func.count()).group_by(User.org_id)).all())
        return [{"id": o.id, "name": o.name, "kind": o.kind, "business_reg": o.business_reg, "status": o.status,
                 "users": counts.get(o.id, 0)} for o in db.execute(select(Org).order_by(Org.created_at)).scalars()]

    @app.post("/api/v1/admin/orgs/{org_id}/status")
    async def admin_set_status(org_id: str, request: Request, p: Principal = Depends(require_roles_csrf("platform_admin")),
                               db=Depends(get_db)):
        body = await request.json()
        status = body.get("status")
        if status not in ("active", "suspended"):
            raise HTTPException(422, "status must be active or suspended")
        org = db.get(Org, org_id)
        if org is None:
            raise HTTPException(404, "org not found")
        if org.kind == "platform":
            raise HTTPException(422, "the platform org cannot be suspended")
        org.status = status
        db.commit()
        audit(db, "org.status", p.user, org.id, status=status)
        return {"ok": True}

    @app.get("/api/v1/admin/audit")
    def admin_audit(p: Principal = Depends(require_roles("platform_admin")), db=Depends(get_db)):
        from .models import AuditEvent
        ok, bad = verify_audit_chain(db)
        rows = db.execute(select(AuditEvent).order_by(AuditEvent.seq.desc()).limit(200)).scalars()
        return {"chain_ok": ok, "first_bad_seq": bad,
                "events": [{"seq": e.seq, "action": e.action, "actor": e.actor_user_id, "org": e.org_id,
                            "detail": e.detail} for e in rows]}

    # ----- minimal pages (full UI in M6) -----
    @app.get("/")
    def home(request: Request):
        return RedirectResponse("/app" if request.cookies.get(SESSION_COOKIE) else "/login", status_code=303)

    @app.get("/login")
    def login_page(request: Request):
        return templates.TemplateResponse(request, "login.html", {"title": "Sign in"})

    @app.get("/signup")
    def signup_page(request: Request):
        return templates.TemplateResponse(request, "signup.html", {"title": "Create an account"})

    @app.get("/app")
    def app_page(request: Request, db=Depends(get_db)):
        from .security import load_session
        s = load_session(db, request.cookies.get(SESSION_COOKIE))
        if s is None:
            return RedirectResponse("/login", status_code=303)
        user = db.get(User, s.user_id)
        org = db.get(Org, user.org_id)
        return templates.TemplateResponse(request, "app.html", {"title": "Dashboard", "user": user, "org": org,
                                                                "csrf": s.csrf_token})

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    return app
