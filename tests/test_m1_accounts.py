"""M1: accounts, sessions, CSRF, roles, tenant isolation, lockout, suspension, audit chain, migrations."""
from sqlalchemy import text

from conftest import STRONG_PW, login_actor


def test_signup_login_me_and_cookie_flags(client):
    r = client.post("/api/v1/auth/signup", json={"org_name": "Example IT", "org_kind": "provider", "business_reg": "REG-0000001",
                                                 "name": "Pat", "email": "Pat@Provider.test", "password": STRONG_PW})
    assert r.status_code == 201
    r = client.post("/api/v1/auth/login", json={"email": "pat@provider.test", "password": STRONG_PW})
    assert r.status_code == 200
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    me = client.get("/api/v1/me").json()
    assert me["role"] == "provider_admin" and me["org"]["kind"] == "provider" and me["email"] == "pat@provider.test"


def test_signup_validation(client):
    base = {"org_name": "X Ltd", "org_kind": "customer", "name": "A", "email": "a@x.test", "password": STRONG_PW}
    assert client.post("/api/v1/auth/signup", json=dict(base, password="short")).status_code == 422
    assert client.post("/api/v1/auth/signup", json=dict(base, password="alllowercase12345")).status_code == 422
    assert client.post("/api/v1/auth/signup", json=dict(base, org_kind="platform")).status_code == 422
    assert client.post("/api/v1/auth/signup", json=dict(base, email="not-an-email")).status_code == 422
    assert client.post("/api/v1/auth/signup", json=base).status_code == 201
    assert client.post("/api/v1/auth/signup", json=dict(base, email="A@X.test")).status_code == 409


def test_unauthenticated_requests_refused(client):
    for path in ("/api/v1/me", "/api/v1/orgs/me/users", "/api/v1/admin/orgs", "/api/v1/admin/audit"):
        assert client.get(path).status_code == 401, path


def test_wrong_password_then_lockout(client, make_actor, app):
    a = make_actor(email="lock@x.test")
    for _ in range(4):
        assert client.post("/api/v1/auth/login", json={"email": "lock@x.test", "password": "Wrong-Pass-123"}).status_code == 401
    assert client.post("/api/v1/auth/login", json={"email": "lock@x.test", "password": "Wrong-Pass-123"}).status_code == 423
    assert client.post("/api/v1/auth/login", json={"email": "lock@x.test", "password": STRONG_PW}).status_code == 423
    assert client.post("/api/v1/auth/login", json={"email": "nobody@x.test", "password": STRONG_PW}).status_code == 401


def test_login_rate_limit(app, client):
    app.state.login_limiter.per_minute = 3
    codes = [client.post("/api/v1/auth/login", json={"email": "z@x.test", "password": "x"}).status_code
             for _ in range(5)]
    assert codes[-1] == 429


def test_csrf_required_on_state_changes(make_actor):
    a = make_actor()
    body = {"name": "Bo", "email": "bo@x.test", "role": "customer_approver", "password": STRONG_PW}
    assert a.post("/api/v1/orgs/me/users", json=body, csrf=False).status_code == 403
    assert a.post("/api/v1/orgs/me/users", json=body, csrf=False, headers={"X-CSRF-Token": "guess"}).status_code == 403
    assert a.post("/api/v1/orgs/me/users", json=body).status_code == 201
    assert a.post("/api/v1/auth/logout", csrf=False).status_code == 403


def test_content_type_and_origin_guards(make_actor):
    a = make_actor()
    r = a.c.post("/api/v1/orgs/me/users", content=b'{"x":1}', headers={"Content-Type": "text/plain",
                                                                    "X-CSRF-Token": a.csrf})
    assert r.status_code == 415
    r = a.c.post("/api/v1/orgs/me/users", json={}, headers={"Origin": "https://evil.example", "X-CSRF-Token": a.csrf})
    assert r.status_code == 403


def test_role_matrix(make_actor, app, admin):
    cust = make_actor("customer")
    cust.post("/api/v1/orgs/me/users", json={"name": "M", "email": "member@x.test", "role": "customer_member",
                                             "password": STRONG_PW})
    member = login_actor(app, "member@x.test")
    assert member.get("/api/v1/orgs/me/users").status_code == 403
    assert member.post("/api/v1/orgs/me/users", json={"name": "Q", "email": "q@x.test", "role": "customer_admin",
                                                      "password": STRONG_PW}).status_code == 403
    prov = make_actor("provider")
    r = prov.post("/api/v1/orgs/me/users", json={"name": "T", "email": "t@x.test", "role": "customer_approver",
                                                 "password": STRONG_PW})
    assert r.status_code == 422, "providers cannot create customer roles"
    for actor in (cust, prov, member):
        assert actor.get("/api/v1/admin/orgs").status_code == 403
        assert actor.get("/api/v1/admin/audit").status_code == 403
    assert admin.get("/api/v1/admin/orgs").status_code == 200


def test_tenant_isolation(make_actor, app):
    a = make_actor("customer")
    b = make_actor("customer")
    b.post("/api/v1/orgs/me/users", json={"name": "V", "email": "victim@x.test", "role": "customer_member",
                                          "password": STRONG_PW})
    victim_id = next(u["id"] for u in b.get("/api/v1/orgs/me/users").json() if u["email"] == "victim@x.test")
    assert a.post(f"/api/v1/orgs/me/users/{victim_id}/deactivate").status_code == 404
    assert all(u["email"] != "victim@x.test" for u in a.get("/api/v1/orgs/me/users").json())
    assert login_actor(app, "victim@x.test")  # still active


def test_deactivated_user_cannot_sign_in_or_use_session(make_actor, app, client):
    a = make_actor()
    a.post("/api/v1/orgs/me/users", json={"name": "D", "email": "gone@x.test", "role": "customer_member",
                                          "password": STRONG_PW})
    gone = login_actor(app, "gone@x.test")
    uid = next(u["id"] for u in a.get("/api/v1/orgs/me/users").json() if u["email"] == "gone@x.test")
    assert a.post(f"/api/v1/orgs/me/users/{uid}/deactivate").status_code == 200
    assert gone.get("/api/v1/me").status_code == 401
    assert client.post("/api/v1/auth/login", json={"email": "gone@x.test", "password": STRONG_PW}).status_code == 401


def test_admin_suspends_org(make_actor, admin, client):
    a = make_actor("provider", email="sus@x.test")
    org_id = a.get("/api/v1/me").json()["org"]["id"]
    assert admin.post(f"/api/v1/admin/orgs/{org_id}/status", json={"status": "suspended"}).status_code == 200
    assert a.get("/api/v1/me").status_code == 403
    assert client.post("/api/v1/auth/login", json={"email": "sus@x.test", "password": STRONG_PW}).status_code == 403
    assert admin.post(f"/api/v1/admin/orgs/{org_id}/status", json={"status": "active"}).status_code == 200
    assert a.get("/api/v1/me").status_code == 200


def test_logout_ends_session(make_actor):
    a = make_actor()
    assert a.post("/api/v1/auth/logout").status_code == 200
    assert a.get("/api/v1/me").status_code == 401


def test_audit_chain_detects_tampering(make_actor, admin, app):
    make_actor()
    r = admin.get("/api/v1/admin/audit").json()
    assert r["chain_ok"] and len(r["events"]) >= 3
    with app.state.engine.begin() as conn:
        conn.execute(text("UPDATE audit_events SET action = 'tampered' WHERE seq = 1"))
    r = admin.get("/api/v1/admin/audit").json()
    assert r["chain_ok"] is False and r["first_bad_seq"] == 1


def test_migrations_match_models(settings):
    """The migrated schema must equal the SQLAlchemy models (no drift)."""
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext
    from sqlalchemy import create_engine
    from ai2ai_platform.db import Base
    eng = create_engine(settings.database_url)
    with eng.connect() as conn:
        diffs = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    eng.dispose()
    assert diffs == [], diffs


def test_pages_headers_and_static(client, make_actor):
    r = client.get("/login")
    assert r.status_code == 200 and "Sign in" in r.text
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/app", follow_redirects=False).status_code == 303
    a = make_actor()
    assert "Sign out" in a.get("/app").text
