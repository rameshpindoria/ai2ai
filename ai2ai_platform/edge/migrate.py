"""Apply the edge database's own Alembic migrations (separate history from the centre's)."""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def migrate_edge(database_url: str):
    from alembic import command
    from alembic.config import Config
    cfg = Config(os.path.join(ROOT, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(ROOT, "migrations_edge"))
    cfg.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    command.upgrade(cfg, "head")
