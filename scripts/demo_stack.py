"""Run the whole platform locally as three separate processes and set up a ready-to-use demo.

    python scripts/demo_stack.py [--scenario S07] [--agent rulebook|claude] [--minutes 60]

Starts: centre http://localhost:8800 · customer edge http://localhost:8810 · provider runtime (polling).
Creates: platform admin, a verified provider with a listed agent + service, a customer with a registered edge,
and an edge enrolment link for the approver's passkey. Data goes to %LOCALAPPDATA%\\ai2ai-platform\\demo (wiped
at each start; ~/ai2ai-platform/demo outside Windows). All data is fictional; the edge runs the IT simulator.
Step-by-step walkthrough: examples/it-support-demo/README.md"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time

import httpx

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PW = "Demo-Password-2026"
CENTRE, EDGE = "http://localhost:8800", "http://localhost:8810"


def cli(env, *args):
    r = subprocess.run([sys.executable, "-m", "ai2ai_platform.cli", *args], cwd=ROOT, env=env, capture_output=True,
                       text=True, timeout=120)
    if r.returncode:
        raise SystemExit(r.stderr[-1500:])
    return r.stdout.strip()


def wait(url, seconds=40):
    end = time.time() + seconds
    while time.time() < end:
        try:
            if httpx.get(url, timeout=1).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.3)
    raise SystemExit(f"{url} did not start")


class B:
    def __init__(self, base):
        self.c, self.csrf = httpx.Client(base_url=base, timeout=30), None

    def post(self, path, body=None):
        r = self.c.post(path, json=body if body is not None else {},
                        headers={"X-CSRF-Token": self.csrf} if self.csrf else {})
        if r.status_code >= 400:
            raise SystemExit(f"{path}: {r.status_code} {r.text[:300]}")
        return r.json()

    def login(self, email):
        self.csrf = self.post("/api/v1/auth/login", {"email": email, "password": PW})["csrf_token"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", default="S07")
    ap.add_argument("--agent", default="rulebook", choices=["rulebook", "claude"])
    ap.add_argument("--minutes", type=float, default=60)
    a = ap.parse_args()
    base = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "ai2ai-platform", "demo")
    shutil.rmtree(base, ignore_errors=True)
    os.makedirs(base)
    env = dict(os.environ, AI2AI_DATA_DIR=os.path.join(base, "centre"), AI2AI_BASE_URL=CENTRE,
               AI2AI_DATABASE_URL="sqlite:///" + os.path.join(base, "centre.db").replace("\\", "/"),
               AI2AI_ADMIN_PASSWORD=PW)
    procs = [subprocess.Popen([sys.executable, "-m", "ai2ai_platform.cli", "serve-centre", "--port", "8800"], cwd=ROOT, env=env)]
    try:
        wait(f"{CENTRE}/healthz")
        cli(env, "create-admin", "admin@ai2ai.demo", "Platform Admin")
        admin = B(CENTRE)
        admin.login("admin@ai2ai.demo")
        keys_dir = os.path.join(base, "provider-keys")
        pub = json.loads(cli(env, "provider-keys", "--keys-dir", keys_dir))
        prov = B(CENTRE)
        prov.post("/api/v1/auth/signup", {"org_name": "Example Managed IT (fictional)", "org_kind": "provider",
                                          "business_reg": "REG-0000001", "name": "Pat Provider", "email": "pat@provider.demo", "password": PW})
        prov.login("pat@provider.demo")
        for purpose in ("org", "agent", "technician"):
            prov.post("/api/v1/provider/keys", {"purpose": purpose, "public_key": pub[purpose]["public_key"]})
        for kind in ("ISO27001", "PIInsurance"):
            prov.post("/api/v1/provider/evidence", {"kind": kind, "reference": f"{kind}-2026-001", "issuer": "Example Certifier",
                                                    "expires_on": "2030-01-01"})
        prov.post("/api/v1/provider/submit")
        org_id = prov.c.get("/api/v1/me").json()["org"]["id"]
        admin.post(f"/api/v1/admin/providers/{org_id}/decision", {"decision": "approve"})
        sys.path.insert(0, ROOT)
        from ai2ai_platform.cli import provider_keys
        k = provider_keys(keys_dir)
        name = "Claude Code IT agent" if a.agent == "claude" else "RuleBook IT agent"
        card = k["org"].sign({"name": name, "version": "1.0.0", "description": "Dispatched IT support agent",
                              "agent_kid": k["agent"].kid, "build_digest": "b" * 64,
                              "capabilities": {"categories": ["it.accounts", "it.email", "it.printing", "it.network",
                                                              "it.endpoint", "it.files", "it.web", "it.security", "it.backup"],
                                               "connectors": ["it-sim"], "max_level": "D2"}})
        agent_id = prov.post("/api/v1/provider/agents", {"card": card})["id"]
        for cat, title in (("it.printing", "Printer and print-queue fixes"), ("it.accounts", "Accounts, starters and leavers"),
                           ("it.email", "Email and Outlook fixes"), ("it.endpoint", "PC performance and updates"),
                           ("it.network", "Wi-Fi, VPN and network"), ("it.security", "Malware and browser clean-up"),
                           ("it.files", "OneDrive and file shares"), ("it.web", "Website certificates"),
                           ("it.backup", "Backup recovery")):
            prov.post("/api/v1/provider/services", {"agent_id": agent_id, "title": title, "category": cat, "level": "D2",
                                                    "price_text": "$95 per job (demo)"})
        cust = B(CENTRE)
        cust.post("/api/v1/auth/signup", {"org_name": "Demo Customer Ltd", "org_kind": "customer", "name": "Kim Customer",
                                          "email": "kim@customer.demo", "password": PW})
        cust.login("kim@customer.demo")
        corg = cust.c.get("/api/v1/me").json()["org"]
        edge_dir = os.path.join(base, "edge")
        cli(env, "edge-init", "--data-dir", edge_dir, "--org-id", corg["id"], "--org-name", corg["name"],
            "--centre-url", CENTRE, "--port", "8810")
        ea_code = cli(env, "edge-add-user", "--data-dir", edge_dir, "--name", "Edge Admin", "--email", "edge.admin@customer.demo",
                      "--role", "edge_admin")
        ap_code = cli(env, "edge-add-user", "--data-dir", edge_dir, "--name", "Kim Customer", "--email", "kim@customer.demo",
                      "--role", "approver")
        ticket = cli(env, "edge-seed", "--data-dir", edge_dir, "--scenario", a.scenario)
        procs.append(subprocess.Popen([sys.executable, "-m", "ai2ai_platform.cli", "serve-edge", "--data-dir", edge_dir,
                                       "--sim-controls"], cwd=ROOT))
        wait(f"{EDGE}/healthz")
        broker = httpx.get(f"{EDGE}/edge/.well-known/keys").json()["broker"]
        cust.post("/api/v1/customer/edge", {"base_url": EDGE, "broker_public_key": broker["public_key"]})
        procs.append(subprocess.Popen([sys.executable, "-m", "ai2ai_platform.cli", "run-provider", "--keys-dir", keys_dir,
                                       "--centre-url", CENTRE, "--agent", a.agent, "--agent-id", agent_id, "--loop",
                                       "--interval", "1"], cwd=ROOT))
        state = {"centre": CENTRE, "edge": EDGE, "password": PW, "customer": "kim@customer.demo", "provider": "pat@provider.demo",
                 "admin": "admin@ai2ai.demo", "approver_enrol_url": f"{EDGE}/edge/enrol?code={ap_code}",
                 "edge_admin_enrol_code": ea_code, "scenario": a.scenario, "ticket_to_type": ticket, "agent_id": agent_id}
        with open(os.path.join(base, "demo.json"), "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=1)
        print(json.dumps(state, indent=1), flush=True)
        print(f"\nThe simulated fault for {a.scenario} is in place. Running for {a.minutes} minutes. Ctrl+C to stop.",
              flush=True)
        time.sleep(a.minutes * 60)
    except KeyboardInterrupt:
        pass
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()


if __name__ == "__main__":
    main()
