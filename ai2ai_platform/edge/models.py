"""Customer edge data model (its own database, separate from the centre)."""
import uuid
from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from ..db import utcnow


class EdgeBase(DeclarativeBase):
    pass


def new_id() -> str:
    return uuid.uuid4().hex


class EdgeUser(EdgeBase):
    __tablename__ = "edge_users"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200))
    email: Mapped[str] = mapped_column(String(254), unique=True)
    role: Mapped[str] = mapped_column(String(20))  # edge_admin | approver
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Enrolment(EdgeBase):
    """One-time code that lets a person register their passkey (the only way to sign in to the edge)."""
    __tablename__ = "enrolments"
    code_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("edge_users.id", ondelete="CASCADE"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used: Mapped[bool] = mapped_column(Boolean, default=False)


class PasskeyCred(EdgeBase):
    __tablename__ = "passkeys"
    credential_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("edge_users.id", ondelete="CASCADE"), index=True)
    public_key: Mapped[str] = mapped_column(Text)  # base64url COSE key
    sign_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Challenge(EdgeBase):
    __tablename__ = "challenges"
    challenge: Mapped[str] = mapped_column(String(100), primary_key=True)
    purpose: Mapped[str] = mapped_column(String(40))
    binding: Mapped[str] = mapped_column(String(200))
    user_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    expires: Mapped[float] = mapped_column(Float)
    used: Mapped[bool] = mapped_column(Boolean, default=False)


class EdgeSession(EdgeBase):
    __tablename__ = "edge_sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("edge_users.id", ondelete="CASCADE"))
    csrf_token: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class EstateState(EdgeBase):
    """The environment connector's state (the simulator in v1)."""
    __tablename__ = "estate"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    data: Mapped[dict] = mapped_column(JSON)


class Job(EdgeBase):
    __tablename__ = "jobs"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    wo_id: Mapped[str] = mapped_column(String(40), unique=True)
    status: Mapped[str] = mapped_column(String(30))  # drafted|approved|working|input-required|completed|canceled|rejected
    ticket: Mapped[str] = mapped_column(Text)
    level: Mapped[str] = mapped_column(String(4))
    work_order: Mapped[dict] = mapped_column(JSON)
    work_order_env: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    listing_facts: Mapped[dict] = mapped_column(JSON)
    created_by: Mapped[str] = mapped_column(String(32))
    escalated: Mapped[bool] = mapped_column(Boolean, default=False)
    escalation_reason: Mapped[str] = mapped_column(Text, default="")
    provider_statement: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    receipt: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    seeded_state: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # estate at approval (for judging/tests)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class StepUp(EdgeBase):
    __tablename__ = "stepups"
    command_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id", ondelete="CASCADE"), index=True)
    op: Mapped[str] = mapped_column(String(80))
    args: Mapped[dict] = mapped_column(JSON)
    diff: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending|approved|declined|used|voided
    approvals: Mapped[list] = mapped_column(JSON, default=list)
    created: Mapped[float] = mapped_column(Float)


class Change(EdgeBase):
    __tablename__ = "changes"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id", ondelete="CASCADE"), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    op: Mapped[str] = mapped_column(String(80))
    args: Mapped[dict] = mapped_column(JSON)
    command_hash: Mapped[str] = mapped_column(String(64))
    before_digest: Mapped[str] = mapped_column(String(64))
    after_digest: Mapped[str] = mapped_column(String(64))
    snapshot: Mapped[dict] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(20))  # applied | rolled_back


class SeenNonce(EdgeBase):
    __tablename__ = "seen_nonces"
    nonce: Mapped[str] = mapped_column(String(64), primary_key=True)
    seen_at: Mapped[float] = mapped_column(Float)


class JobAudit(EdgeBase):
    """Per-job hash-chained audit log."""
    __tablename__ = "job_audit"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    job_id: Mapped[str] = mapped_column(String(32), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    ts: Mapped[float] = mapped_column(Float)
    actor: Mapped[str] = mapped_column(String(40))
    event: Mapped[str] = mapped_column(String(120))
    detail: Mapped[str] = mapped_column(Text)
    outcome: Mapped[str] = mapped_column(String(10))
    prev: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


class Transparency(EdgeBase):
    __tablename__ = "transparency"
    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[float] = mapped_column(Float)
    kind: Mapped[str] = mapped_column(String(30))
    record_digest: Mapped[str] = mapped_column(String(64))
    prev: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


class AssistantToken(EdgeBase):
    """Lets the customer's own AI assistant (e.g. via MCP) draft and track jobs. It can NEVER approve: approval
    endpoints require a signed-in person and a passkey ceremony."""
    __tablename__ = "assistant_tokens"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("edge_users.id", ondelete="CASCADE"))
    label: Mapped[str] = mapped_column(String(100))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class EdgeNotification(EdgeBase):
    __tablename__ = "edge_notifications"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[float] = mapped_column(Float)
    kind: Mapped[str] = mapped_column(String(40))
    job_id: Mapped[str] = mapped_column(String(32), index=True)
    text: Mapped[str] = mapped_column(Text)
    email_queued: Mapped[bool] = mapped_column(Boolean, default=True)
    read: Mapped[bool] = mapped_column(Boolean, default=False)
