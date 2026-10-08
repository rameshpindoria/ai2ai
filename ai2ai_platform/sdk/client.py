"""AI2AI Provider SDK. Framework- and model-neutral: any agent (an LLM, rules, a human with a console) can use it.

The provider keeps its own keys. The SDK signs every request with them:
- CentreClient: poll for jobs routed to you (signed with your ORG key), acknowledge them.
- EdgeSession: talk DIRECTLY to the customer's edge for one job (signed with your AGENT key + short-lived token).
- JobContext: what an agent sees (ticket, allowed classes, operations) and can do (read, request_change, escalate,
  complete). Results from reads are customer data wrapped as untrusted; `read_data` extracts the JSON."""
import json
import re
import time

from ..core.crypto import Signer, new_nonce

UNTRUSTED_RE = re.compile(r'<untrusted source="[^"]*">\n(.*)\n</untrusted>', re.S)


class SdkError(Exception):
    pass


def _json(resp):
    try:
        return resp.json()
    except Exception:
        return {"detail": resp.text}


class CentreClient:
    def __init__(self, http, centre_url: str, org_key: Signer):
        self.http, self.url, self.key = http, centre_url.rstrip("/"), org_key

    def _signed(self, **payload):
        return {"envelope": self.key.sign(dict(payload, nonce=new_nonce(), ts=time.time()))}

    def poll(self) -> list:
        r = self.http.post(f"{self.url}/api/v1/provider/jobs/poll", json=self._signed(type="Poll"))
        if r.status_code != 200:
            raise SdkError(f"poll failed: {r.status_code} {_json(r).get('detail')}")
        return r.json()["jobs"]

    def lookup(self, wo_id: str) -> dict:
        r = self.http.post(f"{self.url}/api/v1/provider/jobs/lookup", json=self._signed(type="Lookup", wo_id=wo_id))
        if r.status_code != 200:
            raise SdkError(f"lookup failed: {r.status_code}")
        return r.json()

    def ack(self, wo_id: str):
        r = self.http.post(f"{self.url}/api/v1/provider/jobs/ack", json=self._signed(type="Ack", wo_id=wo_id))
        if r.status_code != 200:
            raise SdkError(f"ack failed: {r.status_code}")


class EdgeSession:
    def __init__(self, http, edge_url: str, agent_key: Signer, wo_id: str, poll_interval: float = 0.5,
                 approval_timeout: float = 900):
        self.http, self.url, self.key, self.wo_id = http, edge_url.rstrip("/"), agent_key, wo_id
        self.poll_interval, self.approval_timeout = poll_interval, approval_timeout
        self.token = None

    def _sign(self, **payload):
        return self.key.sign(dict(payload, wo_id=self.wo_id, nonce=new_nonce(), ts=time.time()))

    def get_token(self):
        r = self.http.post(f"{self.url}/agent/v1/token", json={"request": self._sign(type="TokenRequest")})
        if r.status_code != 200:
            raise SdkError(f"no access to this job: {_json(r).get('detail')}")
        self.token = r.json()["token"]

    def _post(self, path, retry=True, **payload):
        if self.token is None:
            self.get_token()
        r = self.http.post(f"{self.url}{path}", json={"token": self.token, "request": self._sign(**payload)})
        if r.status_code == 401 and retry and "expired" in str(_json(r).get("detail")):
            self.get_token()
            return self._post(path, retry=False, **payload)
        if r.status_code >= 400:
            raise SdkError(f"{path} refused: {_json(r).get('detail')}")
        return r.json()

    def job(self):
        return self._post("/agent/v1/job", type="JobRequest")

    def call(self, op, args=None):
        return self._post("/agent/v1/call", type="Call", op=op, args=args or {})

    def request_change(self, op, args=None, wait=True, on_wait=None, stopped=None):
        """Ask for a reversible change. The customer's human sees the exact change and approves or declines it."""
        args = args or {}
        first = self.call(op, args)
        if not first.get("approval_required"):
            return first  # refused (class ceiling, egress...) or not a change at all
        if first.get("status") in ("declined", "used", "voided"):
            return {"ok": False, "reason": f"approval {first['status']}"}
        deadline = time.time() + self.approval_timeout
        try:
            while True:
                res = self._post("/agent/v1/change", type="Change", op=op, args=args)
                if not res.get("waiting") or not wait:
                    return res
                if on_wait:
                    on_wait(True)
                if stopped and stopped():
                    raise SdkError("cancelled by the requester")
                if time.time() > deadline:
                    return {"ok": False, "reason": "timed out waiting for the customer's approval"}
                time.sleep(self.poll_interval)
        finally:
            if on_wait:
                on_wait(False)

    def escalate(self, reason):
        return self._post("/agent/v1/escalate", type="Escalation", reason=reason)

    def complete(self, summary, findings=(), outcome="completed"):
        return self._post("/agent/v1/complete", type="CompletionStatement", summary=summary, findings=list(findings),
                          outcome=outcome)


class JobContext:
    """The agent's view of one job."""

    def __init__(self, session: EdgeSession):
        self.session = session
        info = session.job()
        self.wo_id, self.ticket, self.level = info["wo_id"], info["ticket"], info["level"]
        self.allowed_classes, self.operations = info["allowed_classes"], info["operations"]
        self.actions = []
        self.completed = False
        self.waiting_for_approval = False
        self.stop_requested = False
        self.receipt = None

    def _check_stop(self):
        if self.stop_requested:
            raise SdkError("cancelled by the requester")

    def read(self, op, args=None) -> dict:
        self._check_stop()
        res = self.session.call(op, args)
        self.actions.append(("read", op, args, res.get("ok")))
        return res

    def read_data(self, op, args=None):
        """Read and parse the JSON payload. Returns None if refused or failed."""
        res = self.read(op, args)
        if not res.get("ok"):
            return None
        m = UNTRUSTED_RE.search(res["content"])
        return json.loads(m.group(1)) if m else None

    def request_change(self, op, args=None, wait=True) -> dict:
        self._check_stop()
        res = self.session.request_change(op, args, wait=wait,
                                          on_wait=lambda w: setattr(self, "waiting_for_approval", w),
                                          stopped=lambda: self.stop_requested)
        self.actions.append(("change", op, args, res.get("ok")))
        return res

    def escalate(self, reason):
        self.actions.append(("escalate", None, reason, True))
        return self.session.escalate(reason)

    def complete(self, summary, findings=()):
        self.completed = True
        res = self.session.complete(summary, findings)
        self.receipt = res.get("receipt")
        return res


class ProviderRuntime:
    """Polls the centre, hands each new job to the right agent, makes sure every job ends with a completion."""

    def __init__(self, centre: CentreClient, http_for_edge, agents: dict):
        self.centre, self.http_for_edge, self.agents = centre, http_for_edge, agents  # agent_id -> (Signer, agent)
        self.results = []

    def run_once(self):
        for j in self.centre.poll():
            if j["agent_id"] not in self.agents:
                continue
            self.centre.ack(j["wo_id"])
            key, agent = self.agents[j["agent_id"]]
            session = EdgeSession(self.http_for_edge(j["edge_url"]), j["edge_url"], key, j["wo_id"],
                                  poll_interval=getattr(agent, "poll_interval", 0.5))
            try:
                ctx = JobContext(session)
                agent.handle(ctx)
                if not ctx.completed:
                    ctx.complete("agent finished without a summary")
                self.results.append((j["wo_id"], "done", ctx.actions))
            except SdkError as exc:
                self.results.append((j["wo_id"], f"stopped: {exc}", []))
        return self.results
