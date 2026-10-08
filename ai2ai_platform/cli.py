"""Commands. Each process type runs on its own:

  Centre:    python -m ai2ai_platform.cli migrate | create-admin EMAIL NAME | serve-centre [--port 8800]
  Edge:      python -m ai2ai_platform.cli edge-init --data-dir D --org-id ID --org-name NAME --centre-url URL [--port 8810]
             python -m ai2ai_platform.cli edge-add-user --data-dir D --name N --email E --role approver|edge_admin
             python -m ai2ai_platform.cli serve-edge --data-dir D [--sim-controls]
  Provider:  python -m ai2ai_platform.cli provider-keys --keys-dir K          (prints PUBLIC keys to register)
             python -m ai2ai_platform.cli run-provider --keys-dir K --centre-url URL --agent rulebook|claude|rogue
                                                        --agent-id ID [--loop] [--interval 2]
"""
import argparse
import getpass
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def migrate(database_url: str):
    from alembic import command
    from alembic.config import Config
    cfg = Config(os.path.join(HERE, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(HERE, "migrations"))
    cfg.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    command.upgrade(cfg, "head")


def create_admin(settings, email: str, name: str, password: str):
    from sqlalchemy import select
    from .centre.models import Org, User
    from .centre.security import audit, hash_password, password_problems
    from .db import make_engine, make_session_factory
    probs = password_problems(password, settings.min_password_length)
    if probs:
        raise SystemExit("password needs " + ", ".join(probs))
    db = make_session_factory(make_engine(settings.database_url))()
    try:
        org = db.execute(select(Org).where(Org.kind == "platform")).scalar_one_or_none()
        if org is None:
            org = Org(name="AI2AI Platform", kind="platform")
            db.add(org)
            db.flush()
        if db.execute(select(User).where(User.email == email.lower())).scalar_one_or_none():
            raise SystemExit("an account with this email already exists")
        u = User(org_id=org.id, email=email.lower(), name=name, role="platform_admin",
                 password_hash=hash_password(password))
        db.add(u)
        db.commit()
        audit(db, "admin.created", None, org.id, user=u.id)
        return u.id
    finally:
        db.close()


# ----- edge wiring over HTTP (production path) -----
def _edge_config(data_dir):
    with open(os.path.join(data_dir, "edge.json"), encoding="utf-8") as fh:
        return json.load(fh)


def build_edge_app(data_dir, sim_controls=False):
    import httpx
    from .edge.app import EdgeSettings, create_edge_app
    cfg = _edge_config(data_dir)
    centre = cfg["centre_url"].rstrip("/")
    http = httpx.Client(timeout=15)
    centre_key = http.get(f"{centre}/.well-known/ai2ai/centre.json").json()
    if cfg.get("pinned_centre_kid") and centre_key["kid"] != cfg["pinned_centre_kid"]:
        raise SystemExit("centre key changed since this edge was set up; refusing to start")
    settings = EdgeSettings(data_dir=data_dir, org_id=cfg["org_id"], org_name=cfg["org_name"], base_url=cfg["base_url"],
                            centre_url=centre, sim_controls=sim_controls, https=os.environ.get("AI2AI_HTTPS") == "1",
                            database_url=os.environ.get("AI2AI_EDGE_DATABASE_URL", ""))
    return create_edge_app(
        settings, centre_key,
        lambda: http.get(f"{centre}/.well-known/ai2ai/revocations.json").json()["items"],
        lambda path, env: http.post(f"{centre}{path}", json={"envelope": env}),
        lambda agent_id: http.get(f"{centre}/api/v1/agents/{agent_id}/listing").json())


def edge_add_user(data_dir, name, email, role):
    from .edge.app import EdgeSettings

    from .db import make_engine, make_session_factory
    from .edge.service import EdgeService
    from .core.keystore import KeyStore
    cfg = _edge_config(data_dir)
    s = EdgeSettings(data_dir=data_dir, org_id=cfg["org_id"], org_name=cfg["org_name"], base_url=cfg["base_url"],
                     database_url=os.environ.get("AI2AI_EDGE_DATABASE_URL", ""))
    eng = make_engine(s.database_url)
    from .edge.migrate import migrate_edge
    migrate_edge(s.database_url)
    ks = KeyStore(data_dir)
    svc = EdgeService(s, make_session_factory(eng), {"idp": ks.load_or_create("idp", "customer-idp"),
                                                    "approver": ks.load_or_create("approver", "customer-approver"),
                                                    "broker": ks.load_or_create("broker", "customer-broker")}, {}, list)
    db = svc.sf()
    try:
        u = svc.create_user(db, name, email, role)
        code = svc.new_enrolment(db, u)
        db.commit()
        return code
    finally:
        db.close()
        eng.dispose()


def edge_seed(data_dir, scenario):
    """Demo/testing only: seed one of the use case's scenarios into the edge's environment."""
    from .edge.app import EdgeSettings
    from .edge.models import EstateState
    from .db import make_engine, make_session_factory
    from .usecases import load_connector
    cfg = _edge_config(data_dir)
    s = EdgeSettings(data_dir=data_dir, org_id=cfg["org_id"], org_name=cfg["org_name"], base_url=cfg["base_url"],
                     database_url=os.environ.get("AI2AI_EDGE_DATABASE_URL", ""))
    eng = make_engine(s.database_url)
    from .edge.migrate import migrate_edge
    migrate_edge(s.database_url)
    con = load_connector(s.usecase)
    e = con.new_environment()
    con.scenarios[scenario].seed(e)
    db = make_session_factory(eng)()
    try:
        st = db.get(EstateState, 1)
        if st is None:
            db.add(EstateState(id=1, data=e.snapshot()))
        else:
            st.data = e.snapshot()
        db.commit()
        return con.scenarios[scenario].ticket
    finally:
        db.close()
        eng.dispose()


def provider_keys(keys_dir):
    from .core.keystore import KeyStore
    ks = KeyStore(keys_dir)
    return {"org": ks.load_or_create("org", "provider-org"), "agent": ks.load_or_create("agent", "provider-agent"),
            "technician": ks.load_or_create("technician", "provider-technician")}


def make_agent(kind):
    if kind == "rulebook":
        from .providers.rulebook import RuleBookAgent
        return RuleBookAgent()
    if kind == "claude":
        from .providers.claude_agent import ClaudeCodeAgent
        return ClaudeCodeAgent()
    if kind == "rogue":
        from .providers.rogue import RogueAgent
        return RogueAgent()
    raise SystemExit("agent must be rulebook, claude or rogue")


def run_provider(keys_dir, centre_url, agent_kind, agent_id, loop=False, interval=2.0, max_seconds=None):
    import httpx
    from .sdk.client import CentreClient, ProviderRuntime
    keys = provider_keys(keys_dir)
    http = httpx.Client(timeout=900)
    rt = ProviderRuntime(CentreClient(http, centre_url, keys["org"]), lambda url: http,
                         {agent_id: (keys["agent"], make_agent(agent_kind))})
    started, printed = time.time(), 0
    while True:
        rt.run_once()
        for wo, status, actions in rt.results[printed:]:
            print(json.dumps({"wo_id": wo, "status": status, "actions": len(actions)}), flush=True)
        printed = len(rt.results)
        if not loop or (max_seconds and time.time() - started > max_seconds):
            return rt.results
        time.sleep(interval)


def main(argv=None):
    from .config import Settings
    ap = argparse.ArgumentParser(prog="ai2ai_platform.cli")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("migrate")
    a = sub.add_parser("create-admin")
    a.add_argument("email")
    a.add_argument("name")
    s = sub.add_parser("serve-centre")
    s.add_argument("--port", type=int, default=8800)
    ei = sub.add_parser("edge-init")
    for flag in ("--data-dir", "--org-id", "--org-name", "--centre-url"):
        ei.add_argument(flag, required=True)
    ei.add_argument("--port", type=int, default=8810)
    ei.add_argument("--base-url", default=None, help="public URL of this edge (default http://localhost:PORT)")
    eu = sub.add_parser("edge-add-user")
    for flag in ("--data-dir", "--name", "--email", "--role"):
        eu.add_argument(flag, required=True)
    se = sub.add_parser("serve-edge")
    se.add_argument("--data-dir", required=True)
    se.add_argument("--sim-controls", action="store_true")
    es = sub.add_parser("edge-seed")
    es.add_argument("--data-dir", required=True)
    es.add_argument("--scenario", required=True)
    pk = sub.add_parser("provider-keys")
    pk.add_argument("--keys-dir", required=True)
    rp = sub.add_parser("run-provider")
    for flag in ("--keys-dir", "--centre-url", "--agent", "--agent-id"):
        rp.add_argument(flag, required=True)
    rp.add_argument("--loop", action="store_true")
    rp.add_argument("--interval", type=float, default=2.0)
    rp.add_argument("--max-seconds", type=float, default=None)
    args = ap.parse_args(argv)

    if args.cmd in ("migrate", "create-admin", "serve-centre"):
        settings = Settings()
        if args.cmd == "migrate":
            migrate(settings.database_url)
            print("database is up to date")
        elif args.cmd == "create-admin":
            pw = os.environ.get("AI2AI_ADMIN_PASSWORD") or getpass.getpass("Password: ")
            print("created platform admin", create_admin(settings, args.email, args.name, pw))
        else:
            import uvicorn
            from .centre.app import create_app
            migrate(settings.database_url)
            settings.base_url = os.environ.get("AI2AI_BASE_URL", f"http://localhost:{args.port}")
            uvicorn.run(create_app(settings), host=os.environ.get("AI2AI_BIND_HOST", "127.0.0.1"), port=args.port,
                        log_level="warning")
    elif args.cmd == "edge-init":
        os.makedirs(args.data_dir, exist_ok=True)
        import httpx
        kid = httpx.get(args.centre_url.rstrip("/") + "/.well-known/ai2ai/centre.json", timeout=15).json()["kid"]
        with open(os.path.join(args.data_dir, "edge.json"), "w", encoding="utf-8") as fh:
            json.dump({"org_id": args.org_id, "org_name": args.org_name, "centre_url": args.centre_url,
                       "base_url": args.base_url or f"http://localhost:{args.port}", "port": args.port,
                       "pinned_centre_kid": kid}, fh)
        print("edge configured; centre key pinned:", kid)
    elif args.cmd == "edge-add-user":
        print(edge_add_user(args.data_dir, args.name, args.email, args.role))
    elif args.cmd == "serve-edge":
        import uvicorn
        app = build_edge_app(args.data_dir, args.sim_controls)
        uvicorn.run(app, host=os.environ.get("AI2AI_BIND_HOST", "127.0.0.1"), port=_edge_config(args.data_dir)["port"],
                    log_level="warning")
    elif args.cmd == "edge-seed":
        print(edge_seed(args.data_dir, args.scenario))
    elif args.cmd == "provider-keys":
        print(json.dumps({k: {"kid": s.kid, "public_key": s.public_b64} for k, s in provider_keys(args.keys_dir).items()}))
    elif args.cmd == "run-provider":
        run_provider(args.keys_dir, args.centre_url, args.agent, args.agent_id, args.loop, args.interval,
                     args.max_seconds)


if __name__ == "__main__":
    sys.exit(main())
