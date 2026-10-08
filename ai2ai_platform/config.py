"""Settings. Data (databases, keys, transcripts) lives outside the code folder by default: %LOCALAPPDATA%\ai2ai-platform
on Windows, ~/.local/share/ai2ai-platform elsewhere. Keep it out of cloud-synced folders: sync can corrupt live databases."""
import os
import secrets
from dataclasses import dataclass, field


def default_data_dir() -> str:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~/.local/share")
    return os.path.join(base, "ai2ai-platform")


def _secret_file(data_dir: str, name: str, nbytes: int = 32) -> str:
    """Load a secret from the data dir, creating it on first run. Never stored in the code folder."""
    os.makedirs(data_dir, exist_ok=True)
    path = os.path.join(data_dir, name)
    if not os.path.exists(path):
        with open(path, "w", encoding="ascii") as fh:
            fh.write(secrets.token_urlsafe(nbytes))
    with open(path, encoding="ascii") as fh:
        return fh.read().strip()


@dataclass
class Settings:
    data_dir: str = field(default_factory=lambda: os.environ.get("AI2AI_DATA_DIR") or default_data_dir())
    database_url: str = field(default_factory=lambda: os.environ.get("AI2AI_DATABASE_URL", ""))
    base_url: str = field(default_factory=lambda: os.environ.get("AI2AI_BASE_URL", "http://localhost:8800"))
    https: bool = field(default_factory=lambda: os.environ.get("AI2AI_HTTPS", "0") == "1")
    session_hours: int = 8
    max_failed_logins: int = 5
    lockout_minutes: int = 15
    login_rate_per_minute: int = 20
    min_password_length: int = 12
    secret_key: str = ""

    def __post_init__(self):
        os.makedirs(self.data_dir, exist_ok=True)
        if not self.database_url:
            self.database_url = "sqlite:///" + os.path.join(self.data_dir, "centre.db").replace("\\", "/")
        if not self.secret_key:
            self.secret_key = os.environ.get("AI2AI_SECRET_KEY") or _secret_file(self.data_dir, "secret.key")

    @property
    def allowed_origins(self) -> set:
        return {self.base_url.rstrip("/")}
