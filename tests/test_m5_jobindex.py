"""M5 (centre side): edge registration, signed job notices, signed provider polling, metering, matching."""
from sqlalchemy import text

from ai2ai_platform.core.crypto import Signer, new_nonce
from ai2ai_platform.sdk.client import CentreClient, SdkError

CENTRE = "http://localhost:8800"


def approved(world, ticket="Sam can't sign in"):
    job_id = world.draft(ticket=ticket).json()["id"]
    assert world.approver.approve_job(job_id).status_code == 200
    return job_id


def test_notice_poll_ack(world):
    approved(world)
    assert world.notices[-1] == ("/api/v1/edge/jobs/notice", 201)
    centre = CentreClient(world.centre, CENTRE, world.kit.org_key)
    jobs = centre.poll()
    assert len(jobs) == 1 and jobs[0]["agent_id"] == world.agent_id
    assert set(jobs[0]) == {"wo_id", "agent_id", "edge_url", "level"}, "the centre routes metadata only"
    centre.ack(jobs[0]["wo_id"])
    assert centre.poll() == []


def test_centre_never_stores_task_content(world, app):
    approved(world, ticket="Priya's laptop secret-ticket-marker is slow")
    with app.state.engine.connect() as conn:
        dump = " ".join(str(r) for r in conn.execute(text("SELECT * FROM job_index")))
    assert "secret-ticket-marker" not in dump


def test_forged_and_replayed_notices_refused(world, client):
    fake_edge = Signer("customer-broker")
    env = fake_edge.sign({"type": "JobNotice", "customer_org": world.customer_org["id"], "wo_id": "WO-fake",
                          "agent_id": world.agent_id, "provider_org": "x", "level": "D2", "nonce": new_nonce(),
                          "ts": __import__("time").time()})
    assert client.post("/api/v1/edge/jobs/notice", json={"envelope": env}).status_code == 403
    approved(world)
    path, status = world.notices[-1]
    assert status == 201


def test_poll_requires_verified_provider_key(world, client, make_actor):
    stranger = CentreClient(world.centre, CENTRE, Signer("provider-org"))
    try:
        stranger.poll()
        assert False, "unknown key must be refused"
    except SdkError as exc:
        assert "403" in str(exc)
    centre = CentreClient(world.centre, CENTRE, world.kit.org_key)
    env = {"envelope": world.kit.org_key.sign({"type": "Poll", "nonce": "fixed-nonce-1", "ts": __import__("time").time()})}
    assert client.post("/api/v1/provider/jobs/poll", json=env).status_code == 200
    assert client.post("/api/v1/provider/jobs/poll", json=env).status_code == 403, "replay refused"


def test_other_providers_cannot_see_or_ack_the_job(world, app, make_actor, admin):
    from test_m2_providers import ProviderKit, set_business_reg
    other = make_actor("provider", org_name="Other IT")
    oid = set_business_reg(app, other)
    kit = ProviderKit(other).onboard()
    admin.post(f"/api/v1/admin/providers/{oid}/decision", json={"decision": "approve"})
    approved(world)
    oc = CentreClient(world.centre, CENTRE, kit.org_key)
    assert oc.poll() == []
    wo = CentreClient(world.centre, CENTRE, world.kit.org_key).poll()[0]["wo_id"]
    try:
        oc.ack(wo)
        assert False
    except SdkError:
        pass


def test_metering_after_completion_and_kill(world):
    from edge_kit import AgentKit
    world.seed("S01")
    job_id, agent = world.approved_job()
    world.do_change(job_id, agent, "m365.user.unlock", {"upn": "sam@demo-customer.example"})
    agent.complete("unlocked")
    job2 = approved(world)
    world.approver.post(f"/edge/api/jobs/{job2}/kill")
    usage = world.kit.a.get("/api/v1/provider/usage").json()
    assert usage == [{"agent_id": world.agent_id, "jobs": 2, "completed": 1, "canceled": 1, "changes": 1}]
    cust = world.customer.get("/api/v1/customer/jobs").json()
    assert {j["status"] for j in cust} == {"completed", "canceled"}
    assert all(len(j["receipt_digest"]) in (0, 64) for j in cust)


def test_matching_suggests_categories_and_services(world):
    world.kit.a.post("/api/v1/provider/services", json={"agent_id": world.agent_id, "title": "Printer fixes",
                                                        "category": "it.printing", "level": "D2"})
    world.kit.a.post("/api/v1/provider/services", json={"agent_id": world.agent_id, "title": "Account help",
                                                        "category": "it.accounts", "level": "D2"})
    r = world.customer.get("/api/v1/match", params={"q": "Nobody can print, jobs stuck in the printer queue"}).json()
    assert r["categories"][0] == "it.printing" and r["matches"][0]["title"] == "Printer fixes"
    r = world.customer.get("/api/v1/match", params={"q": "Sam is locked out and cannot sign in"}).json()
    assert r["categories"][0] == "it.accounts" and r["matches"][0]["title"] == "Account help"
