"""Platform centre data model. The centre holds NO customer environment data, task content or agent internals."""
import uuid
from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..db import Base, utcnow

ORG_KINDS = ("customer", "provider", "platform")
ROLES_BY_KIND = {
    "customer": ("customer_admin", "customer_approver", "customer_member"),
    "provider": ("provider_admin", "provider_technician"),
    "platform": ("platform_admin",),
}
ADMIN_ROLES = {"customer_admin", "provider_admin", "platform_admin"}


def new_id() -> str:
    return uuid.uuid4().hex


class Org(Base):
    __tablename__ = "orgs"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200))
    kind: Mapped[str] = mapped_column(String(20))
    business_reg: Mapped[str | None] = mapped_column(String(20), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="active")  # active | suspended
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    users: Mapped[list["User"]] = relationship(back_populates="org")


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("orgs.id", ondelete="CASCADE"), index=True)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200))
    role: Mapped[str] = mapped_column(String(40))
    password_hash: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    org: Mapped[Org] = relationship(back_populates="users")


class Session(Base):
    __tablename__ = "sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)  # sha256 of the cookie value
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ip: Mapped[str] = mapped_column(String(64), default="")


class AuditEvent(Base):
    """Centre audit trail (admin and security actions), hash-chained so edits are detectable."""
    __tablename__ = "audit_events"
    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    actor_user_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    org_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    action: Mapped[str] = mapped_column(String(80))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))
    __table_args__ = (UniqueConstraint("hash"),)


# ----- M2: provider onboarding, verification, credentials, agents, services -----
EVIDENCE_KINDS = ("ISO27001", "SOC2", "CyberEssentials", "PIInsurance", "CyberInsurance")


class ProviderProfile(Base):
    __tablename__ = "provider_profiles"
    org_id: Mapped[str] = mapped_column(ForeignKey("orgs.id", ondelete="CASCADE"), primary_key=True)
    status: Mapped[str] = mapped_column(String(20), default="draft")  # draft|submitted|verified|rejected|suspended
    description: Mapped[str] = mapped_column(String(2000), default="")
    website: Mapped[str] = mapped_column(String(300), default="")
    contact_email: Mapped[str] = mapped_column(String(254), default="")
    review_note: Mapped[str] = mapped_column(String(1000), default="")
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    verified_by: Mapped[str | None] = mapped_column(String(32), nullable=True)


class EvidenceItem(Base):
    """What the provider claims (certificate numbers, policy numbers). The platform admin checks it off-platform."""
    __tablename__ = "evidence_items"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("orgs.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(30))
    reference: Mapped[str] = mapped_column(String(200))
    issuer: Mapped[str] = mapped_column(String(200))
    expires_on: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Credential(Base):
    """A centre-signed verifiable credential about a provider org, issued only after admin verification."""
    __tablename__ = "credentials"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(ForeignKey("orgs.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(30))
    envelope: Mapped[dict] = mapped_column(JSON)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    revoked_reason: Mapped[str] = mapped_column(String(500), default="")


class ProviderKey(Base):
    """PUBLIC keys only. Providers keep their private keys on their own infrastructure."""
    __tablename__ = "provider_keys"
    kid: Mapped[str] = mapped_column(String(80), primary_key=True)
    org_id: Mapped[str] = mapped_column(ForeignKey("orgs.id", ondelete="CASCADE"), index=True)
    purpose: Mapped[str] = mapped_column(String(20))  # org | agent | technician
    public_key: Mapped[str] = mapped_column(String(100))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Agent(Base):
    """An agent listing. Holds the provider-signed card (capabilities + build digest), never prompts or code."""
    __tablename__ = "agents"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("orgs.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    version: Mapped[str] = mapped_column(String(40))
    card: Mapped[dict] = mapped_column(JSON)
    countersig: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="draft")  # draft | listed | withdrawn
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Service(Base):
    __tablename__ = "services"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("orgs.id", ondelete="CASCADE"), index=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(200))
    category: Mapped[str] = mapped_column(String(60))
    level: Mapped[str] = mapped_column(String(4))
    description: Mapped[str] = mapped_column(String(2000), default="")
    price_text: Mapped[str] = mapped_column(String(200), default="")
    status: Mapped[str] = mapped_column(String(20), default="active")  # active | paused
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Revocation(Base):
    """Public revocation list (credential ids, agent ids, org ids, key ids) that edges consult."""
    __tablename__ = "revocations"
    item: Mapped[str] = mapped_column(String(80), primary_key=True)
    kind: Mapped[str] = mapped_column(String(20))
    reason: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ----- M5: customer edges, job index (metadata only), metering, replay protection -----
class CustomerEdge(Base):
    """A customer's registered edge. The centre stores its URL and PUBLIC broker key, nothing else."""
    __tablename__ = "customer_edges"
    org_id: Mapped[str] = mapped_column(ForeignKey("orgs.id", ondelete="CASCADE"), primary_key=True)
    base_url: Mapped[str] = mapped_column(String(300))
    broker_kid: Mapped[str] = mapped_column(String(80))
    broker_public_key: Mapped[str] = mapped_column(String(100))
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class JobIndex(Base):
    """Job metadata for routing and metering. No ticket text, no environment data, no results."""
    __tablename__ = "job_index"
    wo_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    customer_org_id: Mapped[str] = mapped_column(ForeignKey("orgs.id", ondelete="CASCADE"), index=True)
    provider_org_id: Mapped[str] = mapped_column(ForeignKey("orgs.id", ondelete="CASCADE"), index=True)
    agent_id: Mapped[str] = mapped_column(String(32), index=True)
    edge_url: Mapped[str] = mapped_column(String(300))
    level: Mapped[str] = mapped_column(String(4))
    status: Mapped[str] = mapped_column(String(20), default="notified")  # notified | picked_up | completed | canceled
    outcome: Mapped[str] = mapped_column(String(40), default="")
    changes_count: Mapped[int] = mapped_column(Integer, default=0)
    escalated: Mapped[bool] = mapped_column(Boolean, default=False)
    receipt_digest: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CentreNonce(Base):
    __tablename__ = "centre_nonces"
    nonce: Mapped[str] = mapped_column(String(64), primary_key=True)
    seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ----- M7: notifications outbox (in-app; email is queued, not sent, until an email provider is configured) -----
class Notification(Base):
    __tablename__ = "notifications"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("orgs.id", ondelete="CASCADE"), index=True)
    role: Mapped[str] = mapped_column(String(40), default="")  # empty = everyone in the org
    kind: Mapped[str] = mapped_column(String(40))
    text: Mapped[str] = mapped_column(String(500))
    email_queued: Mapped[bool] = mapped_column(Boolean, default=True)
    read: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
