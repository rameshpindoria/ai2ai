"""Builds a full world for edge tests: centre + verified provider with a listed agent + one customer edge."""
import time
import uuid

from fastapi.testclient import TestClient

from ai2ai_platform.core.crypto import Signer, new_nonce
from ai2ai_platform.edge.app import EdgeSettings, create_edge_app
from soft_authenticator import SoftAuthenticator
from test_m2_providers import ProviderKit, set_business_reg

EDGE_ORIGIN = "http://localhost:8810"


class EdgeHuman:
    """A customer person at the edge: enrols a passkey, signs in with it, approves things with it."""

    def __init__(self, app, code):
        self.c = TestClient(app, base_url=EDGE_ORIGIN)
        self.auth = SoftAuthenticator()
        o = self.c.post("/edge/api/enrol/options", json={"code": code}).json()["options"]
        r = self.c.post("/edge/api/enrol/finish", json={"code": code, "credential": self.auth.register(o, EDGE_ORIGIN)})
        assert r.status_code == 200, r.text
        self.login()

    def login(self):
        o = self.c.post("/edge/api/login/options", json={}).json()["options"]
        r = self.c.post("/edge/api/login/finish", json={"credential": self.auth.assert_(o, EDGE_ORIGIN)})
        assert r.status_code == 200, r.text
        self.csrf = r.json()["csrf_token"]

    def post(self, path, json=None, csrf=True):
        return self.c.post(path, json=json if json is not None else {},
                           headers={"X-CSRF-Token": self.csrf} if csrf else {})

    def get(self, path):
        return self.c.get(path)

    def passkey(self, options_path, **kw):
        o = self.post(options_path).json()["options"]
        return self.auth.assert_(o, EDGE_ORIGIN, **kw)

    def approve_job(self, job_id, **kw):
        cred = self.passkey(f"/edge/api/jobs/{job_id}/approve/options", **kw)
        return self.post(f"/edge/api/jobs/{job_id}/approve", {"credential": cred})

    def approve_stepup(self, job_id, chash, technician_approval=None, **kw):
        cred = self.passkey(f"/edge/api/jobs/{job_id}/stepups/{chash}/options", **kw)
        body = {"credential": cred}
        if technician_approval:
            body["technician_approval"] = technician_approval
        return self.post(f"/edge/api/jobs/{job_id}/stepups/{chash}/approve", body)


class AgentKit:
    """The provider's agent runtime: holds the agent private key, signs every request, keeps its token."""

    def __init__(self, edge_client, agent_key: Signer, wo_id: str, clock=time.time):
        self.c, self.key, self.wo_id, self.clock = edge_client, agent_key, wo_id, clock
        self.token = None
        self.last_request = None

    def sign(self, **payload):
        env = self.key.sign(dict(payload, wo_id=self.wo_id, nonce=new_nonce(), ts=self.clock()))
        self.last_request = env
        return env

    def get_token(self):
        r = self.c.post("/agent/v1/token", json={"request": self.sign(type="TokenRequest")})
        if r.status_code == 200:
            self.token = r.json()["token"]
        return r

    def _post(self, path, **payload):
        return self.c.post(path, json={"token": self.token, "request": self.sign(**payload)})

    def job(self):
        return self._post("/agent/v1/job", type="JobRequest")

    def call(self, op, args=None):
        return self._post("/agent/v1/call", type="Call", op=op, args=args or {})

    def change(self, op, args=None):
        return self._post("/agent/v1/change", type="Change", op=op, args=args or {})

    def escalate(self, reason):
        return self._post("/agent/v1/escalate", type="Escalation", reason=reason)

    def complete(self, summary="done", findings=()):
        return self._post("/agent/v1/complete", type="CompletionStatement", summary=summary, findings=list(findings),
                          outcome="completed")


class World:
    def __init__(self, centre_app, centre_client, make_actor, admin, tmp_path, edge_db_url, technician=False,
                 connectors=("it-sim",)):
        self.centre = centre_client
        prov = make_actor("provider", org_name="Example Managed IT")
        org_id = set_business_reg(centre_app, prov)
        self.kit = ProviderKit(prov)
        self.kit.onboard(submit=False)
        self.technician_key = Signer("provider-technician")
        if technician:
            prov.post("/api/v1/provider/keys", json={"purpose": "technician", "public_key": self.technician_key.public_b64})
        assert prov.post("/api/v1/provider/submit").status_code == 200
        assert admin.post(f"/api/v1/admin/providers/{org_id}/decision", json={"decision": "approve"}).status_code == 200
        caps = {"categories": ["it.printing", "it.accounts"], "connectors": list(connectors), "max_level": "D2"}
        self.agent_id = self.kit.register_agent(capabilities=caps).json()["id"]
        self.customer = make_actor("customer", org_name="Demo Customer Ltd")
        self.customer_org = self.customer.get("/api/v1/me").json()["org"]
        self.bundle = self.customer.get(f"/api/v1/agents/{self.agent_id}/listing").json()
        ck = centre_client.get("/.well-known/ai2ai/centre.json").json()
        self.edge_settings = EdgeSettings(data_dir=str(tmp_path / f"edge-{uuid.uuid4().hex[:6]}"),
                                          org_id=self.customer_org["id"], org_name=self.customer_org["name"],
                                          base_url=EDGE_ORIGIN, database_url=edge_db_url, sim_controls=True)
        self.notices = []

        def notify(path, env):
            r = centre_client.post(path, json={"envelope": env})
            self.notices.append((path, r.status_code))
            return r
        self.edge = create_edge_app(self.edge_settings, ck,
                                    lambda: centre_client.get("/.well-known/ai2ai/revocations.json").json()["items"],
                                    notify)
        keys = TestClient(self.edge, base_url=EDGE_ORIGIN).get("/edge/.well-known/keys").json()
        r = self.customer.post("/api/v1/customer/edge", json={"base_url": EDGE_ORIGIN,
                                                              "broker_public_key": keys["broker"]["public_key"]})
        assert r.status_code == 200, r.text
        svc = self.edge.state.svc
        db = svc.sf()
        admin_user = svc.create_user(db, "Edge Admin", "edge.admin@demo-customer.example", "edge_admin")
        code = svc.new_enrolment(db, admin_user)
        approver = svc.create_user(db, "Approver", "approver@demo-customer.example", "approver")
        code2 = svc.new_enrolment(db, approver)
        db.commit()
        db.close()
        self.admin = EdgeHuman(self.edge, code)
        self.approver = EdgeHuman(self.edge, code2)
        self.agent_client = TestClient(self.edge, base_url=EDGE_ORIGIN)

    def seed(self, scenario=None, injections=()):
        r = self.admin.post("/edge/api/sim/reset", {"scenario": scenario, "injections": list(injections)})
        assert r.status_code == 200, r.text
        return r.json()["ticket"]

    def draft(self, ticket="Sam can't sign in", level="D2", cosign=False, bundle=None):
        return self.approver.post("/edge/api/jobs", {"bundle": bundle or self.bundle, "ticket": ticket, "level": level,
                                                     "provider_cosign": cosign})

    def approved_job(self, ticket="Sam can't sign in", level="D2", cosign=False):
        r = self.draft(ticket, level, cosign)
        assert r.status_code == 201, r.text
        job_id, wo = r.json()["id"], r.json()["work_order"]
        assert self.approver.approve_job(job_id).status_code == 200
        agent = AgentKit(self.agent_client, self.kit.agent_key, wo["wo_id"])
        assert agent.get_token().status_code == 200
        return job_id, agent

    def view(self, job_id):
        return self.approver.get(f"/edge/api/jobs/{job_id}").json()

    def estate(self):
        svc = self.edge.state.svc
        db = svc.sf()
        try:
            return svc.load_estate(db)
        finally:
            db.close()

    def auto_human(self, stop, approve=lambda pending: True):
        """Plays the customer's approver: reviews each proposed change and approves it with the passkey (or declines),
        until stop() is true. Returns what was decided."""
        decided = []
        while not stop():
            for j in self.approver.get("/edge/api/jobs").json():
                for p in self.view(j["id"]).get("pending", []):
                    if p["command_hash"] in [d[0] for d in decided]:
                        continue
                    ok = approve(p)
                    decided.append((p["command_hash"], p["op"], ok))
                    if ok:
                        self.approver.approve_stepup(j["id"], p["command_hash"])
                    else:
                        self.approver.post(f"/edge/api/jobs/{j['id']}/stepups/{p['command_hash']}/decline")
            time.sleep(0.05)
        return decided

    def do_change(self, job_id, agent, op, args, **approve_kw):
        """Full step-up: agent requests -> customer approves with passkey -> agent submits."""
        r = agent.call(op, args).json()
        assert r.get("approval_required"), r
        assert self.approver.approve_stepup(job_id, r["command_hash"], **approve_kw).status_code == 200
        return agent.change(op, args).json()
