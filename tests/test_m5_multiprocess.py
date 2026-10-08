"""M5 acceptance: three separate OS processes (centre, customer edge, provider runtime) over real HTTP on localhost.
Nothing is shared in memory: each process has its own keys, data folder and database."""
import json
import os
import socket
import subprocess
import sys
import time

import httpx
import pytest

from soft_authenticator import SoftAuthenticator

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PW = "Correct-Horse-42-battery"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def cli(*args, env=None, check=True):
    r = subprocess.run([sys.executable, "-m", "ai2ai_platform.cli", *args], cwd=ROOT, env=env, capture_output=True,
                       text=True, timeout=120)
    if check and r.returncode != 0:
        raise AssertionError(r.stderr[-2000:])
    return r.stdout.strip()


def wait_up(url, proc, seconds=40):
    end = time.time() + seconds
    while time.time() < end:
        if proc.poll() is not None:
            raise AssertionError(f"process exited: {proc.stderr.read()[-2000:] if proc.stderr else ''}")
        try:
            if httpx.get(url, timeout=1).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.3)
    raise AssertionError(f"{url} did not come up")


class Browser:
    def __init__(self, base):
        self.c = httpx.Client(base_url=base, timeout=30)
        self.csrf = None

    def post(self, path, body=None):
        h = {"X-CSRF-Token": self.csrf} if self.csrf else {}
        return self.c.post(path, json=body if body is not None else {}, headers=h)


def test_three_processes_end_to_end(tmp_path):
    cport, eport = free_port(), free_port()
    centre_url, edge_url = f"http://localhost:{cport}", f"http://localhost:{eport}"
    cenv = dict(os.environ, AI2AI_DATA_DIR=str(tmp_path / "centre"), AI2AI_BASE_URL=centre_url,
                AI2AI_DATABASE_URL="sqlite:///" + str(tmp_path / "centre.db").replace("\\", "/"),
                AI2AI_ADMIN_PASSWORD=PW)
    procs = []
    try:
        procs.append(subprocess.Popen([sys.executable, "-m", "ai2ai_platform.cli", "serve-centre", "--port", str(cport)],
                                      cwd=ROOT, env=cenv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True))
        wait_up(f"{centre_url}/healthz", procs[0])
        cli("create-admin", "admin@platform.test", "Admin", env=cenv)

        admin = Browser(centre_url)
        admin.csrf = admin.post("/api/v1/auth/login", {"email": "admin@platform.test", "password": PW}).json()["csrf_token"]

        # ---- provider company onboarding (keys generated in the PROVIDER's own folder) ----
        keys_dir = str(tmp_path / "provider-keys")
        pub = json.loads(cli("provider-keys", "--keys-dir", keys_dir))
        prov = Browser(centre_url)
        prov.post("/api/v1/auth/signup", {"org_name": "Example Managed IT", "org_kind": "provider", "business_reg": "REG-0000001",
                                          "name": "Pat", "email": "pat@provider.test", "password": PW})
        prov.csrf = prov.post("/api/v1/auth/login", {"email": "pat@provider.test", "password": PW}).json()["csrf_token"]
        for purpose in ("org", "agent"):
            assert prov.post("/api/v1/provider/keys", {"purpose": purpose, "public_key": pub[purpose]["public_key"]}).status_code == 201
        for kind in ("ISO27001", "PIInsurance"):
            prov.post("/api/v1/provider/evidence", {"kind": kind, "reference": "X-1", "issuer": "Cert Co", "expires_on": "2030-01-01"})
        assert prov.post("/api/v1/provider/submit").status_code == 200
        org_id = prov.c.get("/api/v1/me").json()["org"]["id"]
        assert admin.post(f"/api/v1/admin/providers/{org_id}/decision", {"decision": "approve"}).status_code == 200
        from ai2ai_platform.cli import provider_keys
        k = provider_keys(keys_dir)  # the provider's own tooling signs its card locally
        card = k["org"].sign({"name": "RuleBook IT agent", "version": "1.0.0", "description": "rules-based IT agent",
                              "agent_kid": k["agent"].kid, "build_digest": "a" * 64,
                              "capabilities": {"categories": ["it.printing"], "connectors": ["it-sim"], "max_level": "D2"}})
        agent_id = prov.post("/api/v1/provider/agents", {"card": card}).json()["id"]

        # ---- customer company + its own edge process ----
        cust = Browser(centre_url)
        cust.post("/api/v1/auth/signup", {"org_name": "Demo Customer Ltd", "org_kind": "customer", "name": "Kim",
                                          "email": "kim@demo.test", "password": PW})
        cust.csrf = cust.post("/api/v1/auth/login", {"email": "kim@demo.test", "password": PW}).json()["csrf_token"]
        cust_org = cust.c.get("/api/v1/me").json()["org"]
        edge_dir = str(tmp_path / "edge")
        cli("edge-init", "--data-dir", edge_dir, "--org-id", cust_org["id"], "--org-name", cust_org["name"],
            "--centre-url", centre_url, "--port", str(eport))
        admin_code = cli("edge-add-user", "--data-dir", edge_dir, "--name", "Edge Admin", "--email", "ea@demo.test",
                         "--role", "edge_admin")
        appr_code = cli("edge-add-user", "--data-dir", edge_dir, "--name", "Approver", "--email", "ap@demo.test",
                        "--role", "approver")
        procs.append(subprocess.Popen([sys.executable, "-m", "ai2ai_platform.cli", "serve-edge", "--data-dir", edge_dir,
                                       "--sim-controls"], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                      text=True))
        wait_up(f"{edge_url}/healthz", procs[1])
        broker = httpx.get(f"{edge_url}/edge/.well-known/keys").json()["broker"]
        assert cust.post("/api/v1/customer/edge", {"base_url": edge_url, "broker_public_key": broker["public_key"]}).status_code == 200

        def person(code):
            b, a = Browser(edge_url), SoftAuthenticator()
            o = b.post("/edge/api/enrol/options", {"code": code}).json()["options"]
            assert b.post("/edge/api/enrol/finish", {"code": code, "credential": a.register(o, edge_url)}).status_code == 200
            o = b.post("/edge/api/login/options").json()["options"]
            b.csrf = b.post("/edge/api/login/finish", {"credential": a.assert_(o, edge_url)}).json()["csrf_token"]
            return b, a

        ea, _ = person(admin_code)
        ap, ap_auth = person(appr_code)
        ticket = ea.post("/edge/api/sim/reset", {"scenario": "S07"}).json()["ticket"]
        bundle = cust.c.get(f"/api/v1/agents/{agent_id}/listing").json()
        job = ap.post("/edge/api/jobs", {"bundle": bundle, "ticket": ticket, "level": "D2"}).json()
        o = ap.post(f"/edge/api/jobs/{job['id']}/approve/options").json()["options"]
        assert ap.post(f"/edge/api/jobs/{job['id']}/approve", {"credential": ap_auth.assert_(o, edge_url)}).status_code == 200

        # ---- provider runtime: its own process, polls the centre, talks to the edge directly ----
        procs.append(subprocess.Popen([sys.executable, "-m", "ai2ai_platform.cli", "run-provider", "--keys-dir", keys_dir,
                                       "--centre-url", centre_url, "--agent", "rulebook", "--agent-id", agent_id,
                                       "--loop", "--interval", "0.5", "--max-seconds", "90"], cwd=ROOT,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
        approved, end = set(), time.time() + 90
        while time.time() < end:
            v = ap.c.get(f"/edge/api/jobs/{job['id']}").json()
            for p in v["pending"]:
                if p["command_hash"] not in approved:
                    o = ap.post(f"/edge/api/jobs/{job['id']}/stepups/{p['command_hash']}/options").json()["options"]
                    assert ap.post(f"/edge/api/jobs/{job['id']}/stepups/{p['command_hash']}/approve",
                                   {"credential": ap_auth.assert_(o, edge_url)}).status_code == 200
                    approved.add(p["command_hash"])
            if v["status"] == "completed":
                break
            time.sleep(0.3)
        assert v["status"] == "completed", v["audit"][-5:]
        verdict = ap.c.get(f"/edge/api/sim/judge/{job['id']}?scenario=S07").json()
        assert verdict["resolved"], verdict
        assert v["receipt"] and v["chain"]["ok"]
        usage = prov.c.get("/api/v1/provider/usage").json()
        assert usage and usage[0]["completed"] == 1 and usage[0]["changes"] >= 1
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()
