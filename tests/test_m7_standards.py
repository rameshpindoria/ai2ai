"""M7: A2A v1.0.1 (centre discovery card + provider A2A endpoint), customer MCP with assistant tokens,
notifications, and no certificate numbers in public listings."""
import copy
import json
import os
import threading
import time

import pytest
from fastapi.testclient import TestClient

from ai2ai_platform.core.a2a import (CARD_REQUIRED, EXTENSION_URI, IllegalTransition, TaskStateMachine,
                                     card_shape_errors, verify_card)
from ai2ai_platform.core.crypto import SignatureError
from ai2ai_platform.edge.customer_mcp import TOOLS as CUSTOMER_TOOLS, McpCore, make_forward
from ai2ai_platform.providers.rulebook import RuleBookAgent
from ai2ai_platform.sdk.a2a_server import create_provider_a2a_app

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROTO = os.path.join(ROOT, "tests", "fixtures", "a2a-v1.0.1.proto")
HDRS = {"A2A-Version": "1.0", "A2A-Extensions": EXTENSION_URI}
PROVIDER_A2A = "http://provider-a2a.local"


def rpc(method, params, mid=1):
    return {"jsonrpc": "2.0", "id": mid, "method": method, "params": params}


def signed(world, method, ref, key=None):
    """The customer edge signs each A2A call with its broker key (AI2AI-Caller header)."""
    from ai2ai_platform.core.crypto import new_nonce
    signer = key or world.edge.state.svc.broker
    env = signer.sign({"type": "A2ACall", "method": method, "ref": ref, "nonce": new_nonce(), "ts": time.time()})
    return dict(HDRS, **{"AI2AI-Caller": json.dumps(env)})


_RUNNING_A2A_APPS = []


@pytest.fixture(autouse=True)
def _stop_a2a_runners(edge_db_url):
    """Stop provider A2A job threads before this test's edge database is torn down."""
    yield
    while _RUNNING_A2A_APPS:
        _RUNNING_A2A_APPS.pop().state.shutdown()


def a2a_world(world, client):
    """Provider registers a second agent version whose card declares an A2A endpoint, and runs that endpoint."""
    r = world.kit.register_agent(version="1.1.0", capabilities={
        "categories": ["it.printing", "it.accounts"], "connectors": ["it-sim"], "max_level": "D2",
        "a2a_url": f"{PROVIDER_A2A}/a2a"})
    agent_id = r.json()["id"]
    bundle = client.get(f"/api/v1/agents/{agent_id}/listing").json()
    from ai2ai_platform.sdk.client import CentreClient
    app = create_provider_a2a_app(world.kit.org_key, agent_id, world.kit.agent_key, RuleBookAgent(), bundle,
                                  lambda url: world.agent_client, PROVIDER_A2A,
                                  CentreClient(world.centre, "http://localhost:8800", world.kit.org_key), poll_interval=0.05)
    _RUNNING_A2A_APPS.append(app)
    return agent_id, TestClient(app, base_url=PROVIDER_A2A)


# ======================= A2A cards =======================
def test_centre_a2a_card_matches_proto_and_verifies(world, client):
    agent_id, prov = a2a_world(world, client)
    card = client.get(f"/a2a/agents/{agent_id}/agent-card.json").json()
    assert card_shape_errors(card) == []
    ck = client.get("/.well-known/ai2ai/centre.json").json()
    assert verify_card(card, {ck["kid"]: ck["public_key"]})["typ"] == "JOSE"
    ext = card["capabilities"]["extensions"][0]
    assert ext["uri"] == EXTENSION_URI and ext["required"] and ext["params"]["agentId"] == agent_id
    assert client.get(f"/a2a/agents/{world.agent_id}/agent-card.json").status_code == 404, "no A2A url declared"


def test_card_required_fields_match_official_proto():
    block = open(PROTO, encoding="utf-8").read().split("message AgentCard {", 1)[1].split("\n}", 1)[0]
    req = []
    for line in block.splitlines():
        if "REQUIRED" in line and "=" in line:
            parts = line.split("=")[0].split()[-1].split("_")
            req.append(parts[0] + "".join(p.title() for p in parts[1:]))
    assert sorted(req) == sorted(CARD_REQUIRED)


def test_provider_card_signed_by_provider_and_tamper_detected(world, client):
    agent_id, prov = a2a_world(world, client)
    card = prov.get("/.well-known/agent-card.json").json()
    trusted = {world.kit.org_key.kid: world.kit.org_key.public_b64}
    assert verify_card(card, trusted)
    forged = copy.deepcopy(card)
    forged["supportedInterfaces"][0]["url"] = "https://evil.example/a2a"
    with pytest.raises(SignatureError):
        verify_card(forged, trusted)


# ======================= provider A2A endpoint drives a real job =======================
def test_a2a_sendmessage_runs_job_with_passkey_approvals(world, client):
    agent_id, prov = a2a_world(world, client)
    ticket = world.seed("S07")
    r = world.approver.post("/edge/api/jobs", {"bundle": client.get(f"/api/v1/agents/{agent_id}/listing").json(),
                                                "ticket": ticket, "level": "D2"})
    job_id, wo = r.json()["id"], r.json()["work_order"]
    msg = {"message": {"messageId": "m1", "role": "ROLE_USER", "extensions": [EXTENSION_URI],
                       "parts": [{"data": {"workOrderId": wo["wo_id"], "agentId": agent_id,
                                           "edgeUrl": "http://169.254.169.254"},  # ignored: address comes from the centre
                                  "mediaType": "application/json"}]},
           "configuration": {"returnImmediately": True}}
    # before the customer approves, the centre has no job for this provider, so the push is refused
    assert prov.post("/a2a", json=rpc("SendMessage", msg), headers=signed(world, "SendMessage", wo["wo_id"])).json()["error"]
    assert world.approver.approve_job(job_id).status_code == 200
    task = prov.post("/a2a", json=rpc("SendMessage", msg), headers=signed(world, "SendMessage", wo["wo_id"])).json()["result"]["task"]
    assert task["id"] != f"task-{wo['wo_id']}", "task ids are random, not derived from the Work Order"
    seen, done, final = set(), threading.Event(), {}

    def poll():
        end = time.time() + 30
        while time.time() < end:
            t = prov.post("/a2a", json=rpc("GetTask", {"id": task["id"]}), headers=signed(world, "GetTask", task["id"])).json()["result"]
            seen.add(t["status"]["state"])
            if t["status"]["state"] == "TASK_STATE_COMPLETED":
                final.update(t)
                break
            time.sleep(0.05)
        done.set()
    th = threading.Thread(target=poll)
    th.start()
    world.auto_human(done.is_set)
    th.join(30)
    assert "TASK_STATE_INPUT_REQUIRED" in seen and "TASK_STATE_COMPLETED" in seen
    receipt = next(a for a in final["artifacts"] if a["artifactId"] == "receipt")["parts"][0]["data"]
    assert receipt["payload"]["changes_made"][0]["op"] == "printer.queue.clear"
    verdict = world.approver.get(f"/edge/api/sim/judge/{job_id}?scenario=S07").json()
    assert verdict["resolved"], verdict


def test_a2a_caller_must_be_the_customers_edge(world, client):
    from ai2ai_platform.core.crypto import Signer
    agent_id, prov = a2a_world(world, client)
    r = world.approver.post("/edge/api/jobs", {"bundle": client.get(f"/api/v1/agents/{agent_id}/listing").json(),
                                                "ticket": "printer stuck", "level": "D2"})
    job_id, wo = r.json()["id"], r.json()["work_order"]
    world.approver.approve_job(job_id)
    msg = {"message": {"messageId": "m2", "role": "ROLE_USER", "parts": [{"data": {"workOrderId": wo["wo_id"], "agentId": agent_id}}]},
           "configuration": {"returnImmediately": True}}
    assert prov.post("/a2a", json=rpc("SendMessage", msg), headers=HDRS).json()["error"]["code"] == -32010
    stranger = Signer("customer-broker")
    err = prov.post("/a2a", json=rpc("SendMessage", msg), headers=signed(world, "SendMessage", wo["wo_id"], stranger)).json()["error"]
    assert err["code"] == -32010
    h = signed(world, "SendMessage", wo["wo_id"])
    task = prov.post("/a2a", json=rpc("SendMessage", msg), headers=h).json()["result"]["task"]
    assert prov.post("/a2a", json=rpc("SendMessage", msg), headers=h).json()["error"]["code"] == -32010, "replay refused"
    # someone else cannot read or cancel the task
    assert prov.post("/a2a", json=rpc("GetTask", {"id": task["id"]}), headers=signed(world, "GetTask", task["id"], stranger)).json()["error"]["code"] == -32001
    assert prov.post("/a2a", json=rpc("CancelTask", {"id": task["id"]}), headers=HDRS).json()["error"]["code"] == -32001
    ok = prov.post("/a2a", json=rpc("CancelTask", {"id": task["id"]}), headers=signed(world, "CancelTask", task["id"])).json()
    assert ok["result"]["status"]["state"] == "TASK_STATE_CANCELED"
    assert "Traceback" not in json.dumps(ok) and "kill switch" not in json.dumps(ok)


def test_a2a_protocol_errors(world, client):
    agent_id, prov = a2a_world(world, client)
    good = {"message": {"messageId": "m", "role": "ROLE_USER",
                        "parts": [{"data": {"workOrderId": "WO-x", "agentId": agent_id}}]}}
    assert prov.post("/a2a", json=rpc("SendMessage", good), headers={"A2A-Version": "0.3"}).json()["error"]["code"] == -32009
    assert prov.post("/a2a", json=rpc("SendMessage", good), headers={"A2A-Version": "1.0"}).json()["error"]["code"] == -32008
    bad = copy.deepcopy(good)
    bad["message"]["parts"][0]["data"]["agentId"] = "someone-else"
    assert prov.post("/a2a", json=rpc("SendMessage", bad), headers=HDRS).json()["error"]["code"] == -32602
    assert prov.post("/a2a", json=rpc("SendMessage", good), headers=HDRS).json()["error"]["code"] == -32602, "unknown WO"
    assert prov.post("/a2a", json=rpc("GetTask", {"id": "nope"}), headers=HDRS).json()["error"]["code"] == -32001
    assert prov.post("/a2a", json=rpc("SubscribeToTask", {}), headers=HDRS).json()["error"]["code"] == -32004
    assert prov.post("/a2a", json=rpc("Bogus", {}), headers=HDRS).json()["error"]["code"] == -32601


def test_illegal_task_transitions():
    sm = TaskStateMachine()
    sm.move("TASK_STATE_SUBMITTED")
    sm.move("TASK_STATE_WORKING")
    sm.move("TASK_STATE_COMPLETED")
    with pytest.raises(IllegalTransition):
        sm.move("TASK_STATE_WORKING")
    with pytest.raises(IllegalTransition):
        TaskStateMachine().move("TASK_STATE_COMPLETED")


# ======================= customer MCP + assistant tokens =======================
def test_customer_mcp_can_draft_and_track_but_never_approve(world, client):
    world.seed("S01")
    token = world.approver.post("/edge/api/assistant-tokens", {"label": "my Claude"}).json()["token"]
    world.edge.state.svc.fetch_listing = lambda aid: client.get(f"/api/v1/agents/{aid}/listing").json()
    world.kit.a.post("/api/v1/provider/services", json={"agent_id": world.agent_id, "title": "Account help",
                                                        "category": "it.accounts", "level": "D2"})

    class Http:  # route to the right in-process app by URL
        def get(self, url, **kw):
            return (client if url.startswith("http://localhost:8800") else world.agent_client).get(url, **kw)

        def post(self, url, **kw):
            return (client if url.startswith("http://localhost:8800") else world.agent_client).post(url, **kw)

    core = McpCore(make_forward(Http(), "http://localhost:8800", "http://localhost:8810", token))
    names = {t["name"] for t in core.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]}
    assert names == {"find_providers", "request_service", "job_status", "get_result"}
    assert core.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "approve_job",
                                                                                       "arguments": {}}})["error"]

    def call(name, args):
        return core.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": name, "arguments": args}})["result"]
    found = call("find_providers", {"issue": "Sam is locked out and cannot sign in"})["content"][0]["text"]
    assert "Account help" in found and world.agent_id in found
    drafted = call("request_service", {"agent_id": world.agent_id, "ticket": "Sam is locked out", "level": "D2"})
    text = drafted["content"][0]["text"]
    assert "NOT approved" in text and "passkey" in text
    job_id = text.split("(job ")[1].split(")")[0]
    assert "drafted" in call("job_status", {"job_id": job_id})["content"][0]["text"]
    # the token cannot be used on approval endpoints (they need a signed-in person + passkey)
    r = world.agent_client.post(f"/edge/api/jobs/{job_id}/approve", json={"credential": {}},
                                headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401
    r = world.agent_client.post("/edge/api/assistant/jobs", json={"agent_id": world.agent_id, "ticket": "x"},
                                headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 401


# ======================= notifications =======================
def test_notifications_on_both_sides(world, client, admin):
    msgs = [n["kind"] for n in world.kit.a.get("/api/v1/notifications").json()]
    assert "provider.verified" in msgs
    assert any(n["kind"] == "provider.submitted" for n in admin.get("/api/v1/notifications").json())
    assert all(n["kind"] != "provider.submitted" for n in world.customer.get("/api/v1/notifications").json())
    world.seed("S01")
    job_id, agent = world.approved_job()
    agent.call("m365.user.unlock", {"upn": "sam@demo-customer.example"})
    agent.escalate("needs a person")
    agent.complete("done")
    kinds = [n["kind"] for n in world.approver.get("/edge/api/notifications").json()]
    assert {"approval.needed", "job.escalated", "job.completed"} <= set(kinds)


def test_public_listing_contains_no_certificate_numbers(world, client):
    bundle = json.dumps(client.get(f"/api/v1/agents/{world.agent_id}/listing").json())
    assert "ISO27001-123" not in bundle and "PIInsurance-123" not in bundle
