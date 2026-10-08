"""Authentication, sessions, CSRF, roles and the centre audit chain."""
import hashlib
import hmac
import json
import secrets
import threading
import time
from datetime import timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import Depends, HTTPException, Request
from sqlalchemy import select

from ..db import utcnow
from .models import AuditEvent, Org, Session, User

SESSION_COOKIE = "ai2ai_session"
CSRF_HEADER = "X-CSRF-Token"
GENESIS = "0" * 64
_ph = PasswordHasher()
_DUMMY_HASH = _ph.hash("timing-equaliser-not-a-real-password")


# ----- passwords -----
def hash_password(pw: str) -> str:
    return _ph.hash(pw)


def check_password(pw_hash: str, pw: str) -> bool:
    try:
        return _ph.verify(pw_hash, pw)
    except (VerifyMismatchError, InvalidHashError):
        return False


def password_problems(pw: str, min_len: int) -> list:
    probs = []
    if len(pw) < min_len:
        probs.append(f"at least {min_len} characters")
    if pw.lower() == pw or pw.upper() == pw:
        probs.append("mixed upper and lower case")
    if not any(c.isdigit() for c in pw):
        probs.append("at least one digit")
    return probs


# ----- login rate limiting (per client IP, in memory) -----
class RateLimiter:
    def __init__(self, per_minute: int):
        self.per_minute = per_minute
        self._hits = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            if len(self._hits) > 10_000:  # bound memory: forget clients with no hits in the last minute
                self._hits = {k: v for k, v in self._hits.items() if v and now - v[-1] < 60}
            hits = [t for t in self._hits.get(key, []) if now - t < 60]
            if len(hits) >= self.per_minute:
                self._hits[key] = hits
                return False
            hits.append(now)
            self._hits[key] = hits
            return True


# ----- sessions -----
def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(db, user: User, hours: int, ip: str):
    token = secrets.token_urlsafe(32)
    s = Session(token_hash=_token_hash(token), user_id=user.id, csrf_token=secrets.token_urlsafe(32),
                expires_at=utcnow() + timedelta(hours=hours), ip=ip)
    db.add(s)
    db.commit()
    return token, s


def _aware(dt):
    from datetime import timezone
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def load_session(db, token: str | None):
    if not token:
        return None
    s = db.get(Session, _token_hash(token))
    if s is None or _aware(s.expires_at) < utcnow():
        return None
    return s


def end_session(db, token: str | None):
    s = db.get(Session, _token_hash(token)) if token else None
    if s:
        db.delete(s)
        db.commit()


# ----- audit chain -----
def audit(db, action: str, actor: User | None = None, org_id: str | None = None, **detail):
    last = db.execute(select(AuditEvent).order_by(AuditEvent.seq.desc()).limit(1)).scalar_one_or_none()
    prev = last.hash if last else GENESIS
    body = {"action": action, "actor": actor.id if actor else None, "org": org_id, "detail": detail,
            "ts": utcnow().isoformat(), "prev": prev}
    h = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    ev = AuditEvent(actor_user_id=body["actor"], org_id=org_id, action=action, detail=dict(detail, ts=body["ts"]),
                    prev_hash=prev, hash=h)
    db.add(ev)
    db.commit()
    return ev


def verify_audit_chain(db):
    prev = GENESIS
    for ev in db.execute(select(AuditEvent).order_by(AuditEvent.seq)).scalars():
        detail = dict(ev.detail)
        ts = detail.pop("ts", "")
        body = {"action": ev.action, "actor": ev.actor_user_id, "org": ev.org_id, "detail": detail, "ts": ts,
                "prev": prev}
        h = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if ev.prev_hash != prev or ev.hash != h:
            return False, ev.seq
        prev = ev.hash
    return True, None


# ----- request dependencies -----
def get_db(request: Request):
    db = request.app.state.session_factory()
    try:
        yield db
    finally:
        db.close()


class Principal:
    def __init__(self, user: User, org: Org, session: Session):
        self.user, self.org, self.session = user, org, session

    @property
    def role(self):
        return self.user.role


def current_principal(request: Request, db=Depends(get_db)) -> Principal:
    s = load_session(db, request.cookies.get(SESSION_COOKIE))
    if s is None:
        raise HTTPException(401, "sign in required")
    user = db.get(User, s.user_id)
    if user is None or not user.is_active:
        raise HTTPException(401, "sign in required")
    org = db.get(Org, user.org_id)
    if org is None or org.status != "active":
        raise HTTPException(403, "organisation suspended")
    return Principal(user, org, s)


async def require_csrf(request: Request, p: Principal = Depends(current_principal)) -> Principal:
    sent = request.headers.get(CSRF_HEADER)
    if sent is None and request.headers.get("content-type", "").startswith(
            ("application/x-www-form-urlencoded", "multipart/form-data")):
        sent = (await request.form()).get("csrf_token")
    if not sent or not hmac.compare_digest(str(sent), p.session.csrf_token):
        raise HTTPException(403, "CSRF token missing or invalid")
    return p


def require_roles(*roles):
    def dep(p: Principal = Depends(current_principal)) -> Principal:
        if p.role not in roles:
            raise HTTPException(403, "not allowed for your role")
        return p
    return dep


def require_roles_csrf(*roles):
    async def dep(p: Principal = Depends(require_csrf)) -> Principal:
        if p.role not in roles:
            raise HTTPException(403, "not allowed for your role")
        return p
    return dep


def endpoint_url_problem(url: str, production: bool, path_allowed: bool = False):
    """Why a party-supplied endpoint URL must not be stored or vouched for, or None if it is acceptable.

    Other parties' runtimes call these URLs, so a hostile value could point them at internal services (SSRF) or at a
    non-HTTP scheme. In production: https only, and no localhost or private, loopback, link-local or reserved IP
    literals. In development (http): plain http to any host is allowed. Hostnames that RESOLVE to private addresses
    are not caught here; callers should also restrict egress."""
    import ipaddress
    import re
    from urllib.parse import urlsplit
    if not isinstance(url, str) or len(url) > 300:
        return "URL missing or too long"
    pattern = r"^https?://[A-Za-z0-9.\-]+(:\d+)?(/[A-Za-z0-9._~\-/]*)?$" if path_allowed else \
        r"^https?://[A-Za-z0-9.\-]+(:\d+)?/?$"
    if not re.match(pattern, url):
        return "must be a plain http(s) URL" + ("" if path_allowed else " origin, e.g. https://edge.example.com")
    parts = urlsplit(url)
    if not production:
        return None
    if parts.scheme != "https":
        return "must use https"
    host = (parts.hostname or "").lower().rstrip(".")
    if host == "localhost" or host.endswith(".localhost"):
        return "must not point at localhost"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # Not a canonical IP literal. Resolvers still accept shorthand forms (2130706433, 0x7f000001, 127.1, 0177.0.0.1)
        # that the ipaddress module rejects, so a hostname must have a dot and end in an alphabetic top-level label.
        # Single-label names ("intranet") can resolve through DNS search domains to internal hosts.
        if "." not in host or not re.fullmatch(r"[a-z]{2,63}", host.rsplit(".", 1)[-1]):
            return "must be a DNS hostname or a canonical public IP address"
        return None
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
        return "must not point at a private or internal address"
    return None
