"""The generic connector seam: use-case registry, the IT support connector, unknown operations default to destructive."""
import pytest

from ai2ai_platform.connector import DEFAULT_CLASS, OpError
from ai2ai_platform.usecases import REGISTRY, category_words, default_category, load_connector
from ai2ai_platform.usecases.it_support import ops


def test_registry_loads_the_reference_use_case():
    con = load_connector()
    assert con.name == "it_support" and "it_support" in REGISTRY
    with pytest.raises(ValueError):
        load_connector("no-such-use-case")


def test_unknown_operations_are_destructive():
    con = load_connector("it_support")
    assert DEFAULT_CLASS == "destructive"
    assert con.class_of("totally.made.up") == "destructive"
    assert con.class_of("m365.users.list") == "read"


def test_connector_runs_operations_and_round_trips_state():
    con = load_connector("it_support")
    env = con.new_environment()
    before = env.digest()
    users = con.run(env, "m365.users.list", {})
    assert users and env.digest() == before  # a read changes nothing
    snap = env.snapshot()
    restored = con.new_environment(snap)
    assert restored.digest() == before
    with pytest.raises(OpError):  # the use case's errors are the generic OpError
        con.run(env, "totally.made.up", {})
    assert issubclass(ops.OpError, OpError)


def test_catalogue_has_no_handlers_and_descriptions_come_from_the_connector():
    con = load_connector("it_support")
    cat = con.catalogue()
    assert cat and all("fn" not in c for c in cat)
    assert con.describe("m365.users.list") == ops.OPS["m365.users.list"]["description"]


def test_matching_vocabulary_comes_from_use_cases():
    words = category_words()
    assert "it.printing" in words and default_category() in words


# ----- a non-IT use case through the whole customer edge -----
@pytest.fixture
def toy_world(app, client, make_actor, admin, tmp_path, edge_db_url, monkeypatch):
    from ai2ai_platform import usecases
    from edge_kit import World
    monkeypatch.setitem(usecases.REGISTRY, "toy_ledger", {"connector": "toy_usecase:ToyConnector",
                                                          "vocabulary": "toy_usecase"})
    monkeypatch.setenv("AI2AI_USECASE", "toy_ledger")
    w = World(app, client, make_actor, admin, tmp_path, edge_db_url, connectors=("toy-ledger",))
    yield w
    w.edge.state.engine.dispose()


def test_a_non_it_use_case_runs_through_broker_approvals_and_receipts(toy_world):
    w = toy_world
    assert w.edge.state.svc.connector.name == "toy_ledger"
    assert "books.ledger" in category_words()
    job_id, agent = w.approved_job(ticket="Please annotate invoice INV-1")
    job = agent.job().json()
    assert {o["name"] for o in job["operations"]} == {"ledger.read", "ledger.note", "ledger.wipe"}

    r = agent.call("ledger.read").json()
    assert r["ok"] and r["content"].startswith("<untrusted") and "INV-1" in r["content"]
    assert agent.call("ledger.wipe").json()["ok"] is False          # destructive: refused at D2
    assert agent.call("ledger.unknown").json()["ok"] is False       # unknown: treated as destructive

    res = w.do_change(job_id, agent, "ledger.note", {"id": "INV-1", "note": "checked"})
    assert res["ok"], res
    assert w.estate().data["entries"][0]["note"] == "checked"

    receipt = agent.complete("annotated INV-1").json()["receipt"]["payload"]
    assert [c["op"] for c in receipt["changes_made"]] == ["ledger.note"]
    assert "ledger.wipe" in receipt["operations_denied"]


# ----- party-supplied endpoint URLs (edge base_url, provider a2a_url) -----
def test_endpoint_urls_are_restricted_in_production():
    from ai2ai_platform.centre.security import endpoint_url_problem as p
    assert p("http://localhost:8810", production=False) is None          # development
    assert p("https://edge.example.com", production=True) is None
    assert p("https://edge.example.com.", production=True) is None
    assert p("https://8.8.8.8", production=True) is None                  # canonical public IP literal
    for bad in ("http://edge.example.com", "https://localhost", "https://127.0.0.1", "https://10.0.0.5",
                "https://169.254.169.254", "https://192.168.1.1:8443", "https://[::1]", "javascript:alert(1)",
                "https://edge.example.com/path", "https://2130706433", "https://0x7f000001", "https://127.1",
                "https://0177.0.0.1", "https://localhost.", "https://intranet"):
        assert p(bad, production=True), bad
    assert p("https://agents.example.com/a2a", production=True, path_allowed=True) is None
    assert p("https://10.1.2.3/a2a", production=True, path_allowed=True)


def test_an_agent_without_the_edges_connector_cannot_be_hired(toy_world):
    other = toy_world.kit.register_agent(name="IT-only agent").json()["id"]  # default card declares it-sim only
    bundle = toy_world.customer.get(f"/api/v1/agents/{other}/listing").json()
    r = toy_world.draft(bundle=bundle)
    assert r.status_code == 422 and "connector" in r.json()["detail"], r.text
