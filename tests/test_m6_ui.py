"""M6: pages render for each role, are protected, use no unsafe DOM sinks, and the agent_id drafting path works."""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JS = [os.path.join(ROOT, "ai2ai_platform", "centre", "static", "app.js"),
      os.path.join(ROOT, "ai2ai_platform", "edge", "static", "edge.js")]


def test_no_unsafe_dom_sinks_in_any_script():
    for path in JS:
        src = open(path, encoding="utf-8").read()
        for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
            assert sink not in src, f"{os.path.basename(path)} uses {sink}"
        assert "textContent" in src


def test_no_inline_scripts_in_templates():
    for d in ("centre", "edge"):
        tdir = os.path.join(ROOT, "ai2ai_platform", d, "templates")
        for name in os.listdir(tdir):
            html = open(os.path.join(tdir, name), encoding="utf-8").read()
            assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html), f"{d}/{name} has an inline script"
            assert not re.search(r"\son[a-z]+=", html), f"{d}/{name} has an inline event handler"


def test_centre_dashboards_per_role(make_actor, admin):
    cust, prov = make_actor("customer"), make_actor("provider")
    assert "Get an IT issue fixed" in cust.get("/app").text
    assert "Verification" in prov.get("/app").text and "Signed agent card" in prov.get("/app").text
    assert "Providers awaiting verification" in admin.get("/app").text


def test_edge_pages_protected_and_render(world):
    from fastapi.testclient import TestClient
    from edge_kit import EDGE_ORIGIN
    anon = TestClient(world.edge, base_url=EDGE_ORIGIN)
    for path in ("/edge/", "/edge/new?agent=x", "/edge/jobs/abc"):
        r = anon.get(path, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/edge/login"
    assert "Sign in with your passkey" in anon.get("/edge/login").text
    assert anon.get("/edge/static/edge.js").status_code == 200
    page = world.approver.get(f"/edge/new?agent={world.agent_id}&level=D2").text
    assert world.agent_id in page and "Prepare Work Order" in page
    assert "default-src 'self'" in anon.get("/edge/login").headers["content-security-policy"]


def test_edge_drafts_by_agent_id(world, client):
    world.edge.state.svc.fetch_listing = lambda aid: client.get(f"/api/v1/agents/{aid}/listing").json()
    r = world.approver.post("/edge/api/jobs", {"agent_id": world.agent_id, "ticket": "Printer is stuck", "level": "D2"})
    assert r.status_code == 201, r.text
    assert r.json()["work_order"]["agent_id"] == world.agent_id


def test_listing_is_public_but_only_for_listed_agents(world, client):
    assert client.get(f"/api/v1/agents/{world.agent_id}/listing").status_code == 200
    assert client.get("/api/v1/agents/does-not-exist/listing").status_code == 404
