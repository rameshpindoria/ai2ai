"""Test fixtures. Default: a fresh SQLite database per test. With AI2AI_TEST_PG=1: a fresh database per test on a
real embedded PostgreSQL server (pgserver), data kept outside the code folder in %LOCALAPPDATA%\\ai2ai-platform\\pgtest."""
import os
import sys
import uuid

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from ai2ai_platform.cli import migrate  # noqa: E402
from ai2ai_platform.config import Settings, default_data_dir  # noqa: E402

USE_PG = os.environ.get("AI2AI_TEST_PG") == "1"
STRONG_PW = "Correct-Horse-42-battery"


@pytest.fixture(scope="session")
def pg_server():
    if not USE_PG:
        yield None
        return
    import pgserver
    srv = pgserver.get_server(os.path.join(default_data_dir(), "pgtest"), cleanup_mode="stop")
    yield srv
    srv.cleanup()


@pytest.fixture
def database_url(tmp_path, pg_server):
    if pg_server is None:
        yield "sqlite:///" + str(tmp_path / "centre.db").replace("\\", "/")
        return
    import psycopg
    name = "t_" + uuid.uuid4().hex[:12]
    base = pg_server.get_uri()
    with psycopg.connect(base, autocommit=True) as c:
        c.execute(f"CREATE DATABASE {name}")
    url = base.rsplit("/", 1)[0].replace("postgresql://", "postgresql+psycopg://", 1) + "/" + name
    yield url
    with psycopg.connect(base, autocommit=True) as c:
        c.execute(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")


@pytest.fixture
def settings(tmp_path, database_url):
    s = Settings(data_dir=str(tmp_path / "data"), database_url=database_url, base_url="http://localhost:8800")
    migrate(s.database_url)
    return s


@pytest.fixture
def app(settings):
    from ai2ai_platform.centre.app import create_app
    a = create_app(settings)
    yield a
    a.state.engine.dispose()


@pytest.fixture
def client(app):
    from fastapi.testclient import TestClient
    with TestClient(app, base_url="http://localhost:8800") as c:
        yield c


class Actor:
    """A signed-in browser: its own cookie jar plus the CSRF token for its session."""

    def __init__(self, app, email, csrf):
        from fastapi.testclient import TestClient
        self.c = TestClient(app, base_url="http://localhost:8800")
        self.email, self.csrf = email, csrf

    def get(self, path, **kw):
        return self.c.get(path, **kw)

    def post(self, path, json=None, csrf=True, **kw):
        headers = kw.pop("headers", {})
        if csrf:
            headers["X-CSRF-Token"] = self.csrf
        return self.c.post(path, json=json if json is not None else {}, headers=headers, **kw)


@pytest.fixture
def make_actor(app, client):
    def _make(kind="customer", email=None, org_name=None, password=STRONG_PW):
        email = email or f"{uuid.uuid4().hex[:8]}@example.test"
        r = client.post("/api/v1/auth/signup", json={"org_name": org_name or f"Org {email}", "org_kind": kind,
                                                     "name": "Test User", "email": email, "password": password})
        assert r.status_code == 201, r.text
        return login_actor(app, email, password)
    return _make


def login_actor(app, email, password=STRONG_PW):
    a = Actor(app, email, None)
    r = a.c.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    a.csrf = r.json()["csrf_token"]
    return a


@pytest.fixture
def admin(app, settings):
    from ai2ai_platform.cli import create_admin
    create_admin(settings, "admin@platform.test", "Platform Admin", STRONG_PW)
    return login_actor(app, "admin@platform.test")


@pytest.fixture
def edge_db_url(tmp_path, pg_server):
    """The customer edge has its own database, separate from the centre's."""
    if pg_server is None:
        yield "sqlite:///" + str(tmp_path / "edge.db").replace("\\", "/")
        return
    import psycopg
    name = "e_" + uuid.uuid4().hex[:12]
    base = pg_server.get_uri()
    with psycopg.connect(base, autocommit=True) as c:
        c.execute(f"CREATE DATABASE {name}")
    yield base.rsplit("/", 1)[0].replace("postgresql://", "postgresql+psycopg://", 1) + "/" + name
    with psycopg.connect(base, autocommit=True) as c:
        c.execute(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")


@pytest.fixture
def world(app, client, make_actor, admin, tmp_path, edge_db_url):
    from edge_kit import World
    w = World(app, client, make_actor, admin, tmp_path, edge_db_url)
    yield w
    w.edge.state.engine.dispose()


@pytest.fixture
def world_tech(app, client, make_actor, admin, tmp_path, edge_db_url):
    from edge_kit import World
    w = World(app, client, make_actor, admin, tmp_path, edge_db_url, technician=True)
    yield w
    w.edge.state.engine.dispose()
